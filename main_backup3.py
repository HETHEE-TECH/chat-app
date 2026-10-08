"""Simple online chat app: group rooms + private messages.

Run:  uvicorn main:app --reload
Open: http://localhost:8000
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).parent
DB_PATH = os.environ.get("CHAT_DB", str(BASE_DIR / "chat.db"))
MAX_MESSAGE_LEN = 2000
HISTORY_LIMIT = 100
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")

app = FastAPI(title="Chat App")


# ---------------------------------------------------------------- database
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT,
                sender TEXT NOT NULL,
                recipient TEXT,
                content TEXT NOT NULL,
                ts REAL NOT NULL,
                has_image INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                bio TEXT DEFAULT '',
                avatar TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room, id);
            CREATE INDEX IF NOT EXISTS idx_msg_dm ON messages(sender, recipient, id);
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                avatar TEXT DEFAULT '😊',
                bio TEXT DEFAULT ''
            );
            """
        )
        conn.execute("INSERT OR IGNORE INTO rooms(name) VALUES ('general')")
        conn.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------------------------------------------------------------- auth
def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def issue_token(conn: sqlite3.Connection, username: str) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO tokens(token, username) VALUES (?, ?)", (token, username))
    conn.commit()
    return token


def user_from_token(token: str | None) -> str | None:
    if not token:
        return None
    with closing(db()) as conn:
        row = conn.execute("SELECT username FROM tokens WHERE token = ?", (token,)).fetchone()
    return row["username"] if row else None


def current_user(authorization: str | None = Header(default=None)) -> str:
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    username = user_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username


class Credentials(BaseModel):
    username: str
    password: str


class RoomIn(BaseModel):
    name: str


class ProfileUpdate(BaseModel):
    bio: str = ""
    avatar: str = ""


@app.post("/api/register")
def register(creds: Credentials):
    username = creds.username.strip()
    if not NAME_RE.match(username):
        raise HTTPException(400, "Username must be 3-20 letters, numbers, _ or -")
    if len(creds.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    salt = secrets.token_bytes(16)
    with closing(db()) as conn:
        try:
            conn.execute(
                "INSERT INTO users(username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, hash_password(creds.password, salt)),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already taken")
        token = issue_token(conn, username)
    return {"token": token, "username": username}


@app.post("/api/login")
def login(creds: Credentials):
    username = creds.username.strip()
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not hmac.compare_digest(
            row["password_hash"], hash_password(creds.password, row["salt"])
        ):
            raise HTTPException(401, "Invalid username or password")
        token = issue_token(conn, username)
    return {"token": token, "username": username}


# ---------------------------------------------------------------- REST data
@app.get("/api/rooms")
def list_rooms(_: str = Depends(current_user)):
    with closing(db()) as conn:
        return [r["name"] for r in conn.execute("SELECT name FROM rooms ORDER BY name")]


@app.post("/api/rooms")
async def create_room(room: RoomIn, _: str = Depends(current_user)):
    name = room.name.strip().lower()
    if not NAME_RE.match(name):
        raise HTTPException(400, "Room name must be 3-20 letters, numbers, _ or -")
    with closing(db()) as conn:
        try:
            conn.execute("INSERT INTO rooms(name) VALUES (?)", (name,))
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Room already exists")
    await manager.broadcast({"type": "room_created", "room": name})
    return {"name": name}


@app.get("/api/users")
def list_users(me: str = Depends(current_user)):
    with closing(db()) as conn:
        rows = conn.execute("SELECT username FROM users WHERE username != ? ORDER BY username", (me,))
        return [r["username"] for r in rows]

@app.get("/api/profile/{username}")
def get_profile(username: str, _: str = Depends(current_user)):
    with closing(db()) as conn:
        row = conn.execute("SELECT avatar, bio FROM profiles WHERE username = ?", (username,)).fetchone()
    if not row:
        return {"username": username, "avatar": "😊", "bio": ""}
    return {"username": username, "avatar": row["avatar"], "bio": row["bio"]}

class ProfileUpdate(BaseModel):
    avatar: str = "😊"
    bio: str = ""

@app.post("/api/profile")
def update_profile(data: ProfileUpdate, me: str = Depends(current_user)):
    avatar = str(data.avatar)[:2]
    bio = str(data.bio)[:200]
    with closing(db()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO profiles(username, avatar, bio) VALUES (?, ?, ?)",
            (me, avatar, bio),
        )
        conn.commit()
    return {"avatar": avatar, "bio": bio}


@app.get("/api/profile/{username}")
def get_profile(username: str, _: str = Depends(current_user)):
    with closing(db()) as conn:
        row = conn.execute("SELECT bio, avatar FROM profiles WHERE username = ?", (username,)).fetchone()
        if not row:
            return {"username": username, "bio": "", "avatar": ""}
        return {"username": username, "bio": row["bio"], "avatar": row["avatar"]}


@app.post("/api/profile")
def update_profile(profile: ProfileUpdate, me: str = Depends(current_user)):
    with closing(db()) as conn:
        conn.execute("INSERT OR REPLACE INTO profiles(username, bio, avatar) VALUES (?, ?, ?)",
                    (me, profile.bio[:500], profile.avatar[:500]))
        conn.commit()
    return {"success": True}


def row_to_message(r: sqlite3.Row) -> dict:
    return {
        "type": "message",
        "kind": "room" if r["room"] else "dm",
        "room": r["room"],
        "sender": r["sender"],
        "recipient": r["recipient"],
        "content": r["content"],
        "ts": r["ts"],
    }


@app.get("/api/history")
def history(
    room: str | None = Query(default=None),
    with_user: str | None = Query(default=None, alias="with"),
    me: str = Depends(current_user),
):
    with closing(db()) as conn:
        if room:
            rows = conn.execute(
                "SELECT * FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?",
                (room, HISTORY_LIMIT),
            ).fetchall()
        elif with_user:
            rows = conn.execute(
                """SELECT * FROM messages
                   WHERE room IS NULL
                     AND ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                   ORDER BY id DESC LIMIT ?""",
                (me, with_user, with_user, me, HISTORY_LIMIT),
            ).fetchall()
        else:
            raise HTTPException(400, "Provide 'room' or 'with'")
    return [row_to_message(r) for r in reversed(rows)]


# ---------------------------------------------------------------- websocket
class ConnectionManager:
    def __init__(self) -> None:
        self.conns: dict[WebSocket, str] = {}

    def online_users(self) -> list[str]:
        return sorted(set(self.conns.values()))

    async def _send(self, ws: WebSocket, payload: dict) -> None:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            self.conns.pop(ws, None)

    async def broadcast(self, payload: dict) -> None:
        for ws in list(self.conns):
            await self._send(ws, payload)

    async def send_to_users(self, usernames: set[str], payload: dict) -> None:
        for ws, name in list(self.conns.items()):
            if name in usernames:
                await self._send(ws, payload)

    async def broadcast_except(self, sender: str, payload: dict) -> None:
        for ws, name in list(self.conns.items()):
            if name != sender:
                await self._send(ws, payload)

    async def announce_presence(self) -> None:
        await self.broadcast({"type": "presence", "online": self.online_users()})


manager = ConnectionManager()


def save_message(room: str | None, sender: str, recipient: str | None, content: str) -> dict:
    ts = time.time()
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO messages(room, sender, recipient, content, ts) VALUES (?, ?, ?, ?, ?)",
            (room, sender, recipient, content, ts),
        )
        conn.commit()
    return {
        "type": "message",
        "kind": "room" if room else "dm",
        "room": room,
        "sender": sender,
        "recipient": recipient,
        "content": content,
        "ts": ts,
    }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query(default="")):
    username = user_from_token(token)
    if not username:
        await ws.close(code=4401)
        return
    await ws.accept()
    manager.conns[ws] = username
    await manager.announce_presence()
    try:
        while True:
            try:
                data = json.loads(await ws.receive_text())
            except json.JSONDecodeError:
                continue
            kind = data.get("type")
            if kind == "typing":
                room = data.get("room")
                to = data.get("to")
                if room:
                    await manager.broadcast_except(
                        username,
                        {"type": "typing", "kind": "room", "room": str(room), "user": username},
                    )
                elif to:
                    await manager.send_to_users(
                        {str(to)}, {"type": "typing", "kind": "dm", "user": username}
                    )
                continue
            content = str(data.get("content", "")).strip()[:MAX_MESSAGE_LEN]
            if not content:
                continue
            if kind == "room":
                room = str(data.get("room", ""))
                with closing(db()) as conn:
                    exists = conn.execute("SELECT 1 FROM rooms WHERE name = ?", (room,)).fetchone()
                if not exists:
                    continue
                await manager.broadcast(save_message(room, username, None, content))
            elif kind == "dm":
                to = str(data.get("to", ""))
                with closing(db()) as conn:
                    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (to,)).fetchone()
                if not exists:
                    continue
                msg = save_message(None, username, to, content)
                await manager.send_to_users({username, to}, msg)
            elif kind == "image":
                # Handle image message
                img_data = str(data.get("image", ""))[:5000]  # Limit to 5KB base64
                room = data.get("room")
                to = data.get("to")
                if room:
                    msg = save_message(room, username, None, img_data)
                    await manager.broadcast(msg)
                elif to:
                    msg = save_message(None, username, to, img_data)
                    await manager.send_to_users({username, to}, msg)
    except WebSocketDisconnect:
        pass
    finally:
        manager.conns.pop(ws, None)
        await manager.announce_presence()


# ---------------------------------------------------------------- frontend
@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")