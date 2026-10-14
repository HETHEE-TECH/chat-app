"""Simple online chat app: group rooms + private messages.

Run:  uvicorn main:app --reload
Open: http://localhost:8000
"""
import base64
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
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from friends import are_friends, ensure_table, make_router as make_friends_router
from groups import can_access_room, ensure_group_tables, make_router as make_groups_router, room_audience

BASE_DIR = Path(__file__).parent
DB_PATH = os.environ.get("CHAT_DB", str(BASE_DIR / "chat.db"))
MAX_MESSAGE_LEN = 2000
MAX_IMAGE_LEN = 1_500_000  # base64 characters (~1 MB)
MAX_PHOTO_LEN = 400_000  # profile photo, base64 characters (~300 KB)
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
                has_image INTEGER DEFAULT 0,
                edited_at REAL DEFAULT NULL,
                deleted INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                bio TEXT DEFAULT '',
                avatar TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS reactions (
                message_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                PRIMARY KEY (message_id, username, emoji)
            );
            CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room, id);
            CREATE INDEX IF NOT EXISTS idx_msg_dm ON messages(sender, recipient, id);
            """
        )
        # migrate older databases that predate edit/delete support
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
        if "edited_at" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN edited_at REAL DEFAULT NULL")
        if "deleted" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0")
        if "has_image" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN has_image INTEGER DEFAULT 0")
        if "reply_to" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER DEFAULT NULL")
        if "read_at" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN read_at REAL DEFAULT NULL")
        pcols = {r["name"] for r in conn.execute("PRAGMA table_info(profiles)")}
        if "read_receipts" not in pcols:
            conn.execute("ALTER TABLE profiles ADD COLUMN read_receipts INTEGER DEFAULT 1")
        if "photo" not in pcols:
            conn.execute("ALTER TABLE profiles ADD COLUMN photo TEXT")
        if "photo_ts" not in pcols:
            conn.execute("ALTER TABLE profiles ADD COLUMN photo_ts REAL")
        conn.execute("INSERT OR IGNORE INTO rooms(name) VALUES ('general')")
        conn.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    ensure_table(db)
    ensure_group_tables(db)


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


class PasswordChange(BaseModel):
    old_password: str
    new_password: str


@app.post("/api/change-password")
def change_password(
    body: PasswordChange,
    me: str = Depends(current_user),
    authorization: str | None = Header(default=None),
):
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    current_token = authorization.removeprefix("Bearer ").strip() if authorization else ""
    with closing(db()) as conn:
        row = conn.execute("SELECT salt, password_hash FROM users WHERE username = ?", (me,)).fetchone()
        # 400 (not 401) on purpose: a 401 would make the browser log the user out
        if not row or not hmac.compare_digest(
            row["password_hash"], hash_password(body.old_password, row["salt"])
        ):
            raise HTTPException(400, "Current password is incorrect")
        salt = secrets.token_bytes(16)
        conn.execute(
            "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
            (salt, hash_password(body.new_password, salt), me),
        )
        # log out every other device/session, keep this one
        conn.execute("DELETE FROM tokens WHERE username = ? AND token != ?", (me, current_token))
        conn.commit()
    return {"success": True}


# ---------------------------------------------------------------- REST data
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
        conn.execute("INSERT INTO profiles(username, bio, avatar) VALUES (?, ?, ?) "
                    "ON CONFLICT(username) DO UPDATE SET bio = excluded.bio, avatar = excluded.avatar",
                    (me, profile.bio[:500], profile.avatar[:500]))
        conn.commit()
    return {"success": True}


class PhotoIn(BaseModel):
    image: str


@app.post("/api/profile/photo")
async def set_photo(body: PhotoIn, me: str = Depends(current_user)):
    img = body.image.strip()
    if not img.startswith("/9j/") or len(img) > MAX_PHOTO_LEN:
        raise HTTPException(400, "Photo must be a JPEG image (max ~300 KB)")
    try:
        raw = base64.b64decode(img, validate=True)
    except Exception:
        raise HTTPException(400, "Invalid image data")
    if not raw.startswith(b"\xff\xd8\xff"):
        raise HTTPException(400, "Photo must be a JPEG image")
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO profiles(username, photo, photo_ts) VALUES (?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET photo = excluded.photo, photo_ts = excluded.photo_ts",
            (me, img, time.time()),
        )
        conn.commit()
    await manager.broadcast({"type": "avatar_updated", "username": me})
    return {"success": True}


@app.delete("/api/profile/photo")
async def remove_photo(me: str = Depends(current_user)):
    with closing(db()) as conn:
        conn.execute("UPDATE profiles SET photo = NULL, photo_ts = NULL WHERE username = ?", (me,))
        conn.commit()
    await manager.broadcast({"type": "avatar_updated", "username": me})
    return {"success": True}


@app.get("/api/avatar/{username}")
def get_avatar(username: str, _: str = Depends(current_user)):
    with closing(db()) as conn:
        row = conn.execute("SELECT photo FROM profiles WHERE username = ?", (username,)).fetchone()
    if not row or not row["photo"]:
        raise HTTPException(404, "No photo")
    return Response(
        content=base64.b64decode(row["photo"]),
        media_type="image/jpeg",
        headers={"Cache-Control": "private, no-cache"},
    )


class MessageEdit(BaseModel):
    content: str


@app.put("/api/messages/{msg_id}")
async def edit_message(msg_id: int, edit: MessageEdit, me: str = Depends(current_user)):
    content = edit.content.strip()[:MAX_MESSAGE_LEN]
    if not content:
        raise HTTPException(400, "Content cannot be empty")
    with closing(db()) as conn:
        row = conn.execute("SELECT sender, room, recipient FROM messages WHERE id = ?", (msg_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Message not found")
        if row["sender"] != me:
            raise HTTPException(403, "Can only edit your own messages")
        edited_at = time.time()
        conn.execute("UPDATE messages SET content = ?, edited_at = ? WHERE id = ?",
                    (content, edited_at, msg_id))
        conn.commit()
    payload = {"type": "message_edited", "id": msg_id, "content": content, "edited_at": edited_at}
    if row["room"]:
        await send_to_room(row["room"], payload)
    else:
        await manager.send_to_users({row["sender"], row["recipient"]}, payload)
    return {"success": True, "edited_at": edited_at}


@app.delete("/api/messages/{msg_id}")
async def delete_message(msg_id: int, me: str = Depends(current_user)):
    with closing(db()) as conn:
        row = conn.execute("SELECT sender, room, recipient FROM messages WHERE id = ?", (msg_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Message not found")
        if row["sender"] != me:
            raise HTTPException(403, "Can only delete your own messages")
        conn.execute("UPDATE messages SET deleted = 1 WHERE id = ?", (msg_id,))
        conn.commit()
    payload = {"type": "message_deleted", "id": msg_id}
    if row["room"]:
        await send_to_room(row["room"], payload)
    else:
        await manager.send_to_users({row["sender"], row["recipient"]}, payload)
    return {"success": True}


REACTION_EMOJIS = ("👍", "❤️", "😂", "😮", "😢", "🙏")


class ReactionIn(BaseModel):
    emoji: str


def reply_preview(conn: sqlite3.Connection, rid: int) -> dict:
    row = conn.execute("SELECT sender, content, deleted FROM messages WHERE id = ?", (rid,)).fetchone()
    if not row or row["deleted"]:
        return {"id": rid, "sender": "", "snippet": "", "deleted": True}
    content = row["content"]
    snippet = "\U0001F4F7 Photo" if content.startswith(("/9j/", "iVBO")) else content[:80]
    return {"id": rid, "sender": row["sender"], "snippet": snippet, "deleted": False}


def valid_reply_id(conn: sqlite3.Connection, reply_to, room, a: str, b):
    """Only allow replying to a message from the SAME conversation."""
    try:
        rid = int(reply_to)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT room, sender, recipient FROM messages WHERE id = ? AND deleted = 0", (rid,)
    ).fetchone()
    if not row:
        return None
    if room is not None:
        return rid if row["room"] == room else None
    if row["room"] is None and {row["sender"], row["recipient"]} == {a, b}:
        return rid
    return None


def reactions_for(conn: sqlite3.Connection, ids: list[int]) -> dict:
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    out: dict = {}
    rows = conn.execute(
        f"SELECT message_id, emoji, username FROM reactions WHERE message_id IN ({marks}) ORDER BY rowid",
        ids,
    )
    for r in rows:
        out.setdefault(r["message_id"], {}).setdefault(r["emoji"], []).append(r["username"])
    return out


def attach_extras(conn: sqlite3.Connection, msgs: list[dict]) -> None:
    rx = reactions_for(conn, [m["id"] for m in msgs])
    for m in msgs:
        m["reactions"] = rx.get(m["id"], {})
        m["reply"] = reply_preview(conn, m["reply_to"]) if m.get("reply_to") else None


@app.post("/api/messages/{msg_id}/react")
async def react_to_message(msg_id: int, body: ReactionIn, me: str = Depends(current_user)):
    """Toggle one emoji reaction of the current user on a message."""
    if body.emoji not in REACTION_EMOJIS:
        raise HTTPException(400, "Unsupported reaction")
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT room, sender, recipient, deleted FROM messages WHERE id = ?", (msg_id,)
        ).fetchone()
        if not row or row["deleted"]:
            raise HTTPException(404, "Message not found")
        if row["room"]:
            allowed = can_access_room(conn, row["room"], me)
        else:
            other = row["recipient"] if row["sender"] == me else row["sender"]
            allowed = me in (row["sender"], row["recipient"]) and are_friends(conn, me, other)
        if not allowed:
            raise HTTPException(403, "You cannot react to this message")
        exists = conn.execute(
            "SELECT 1 FROM reactions WHERE message_id = ? AND username = ? AND emoji = ?",
            (msg_id, me, body.emoji),
        ).fetchone()
        if exists:
            conn.execute(
                "DELETE FROM reactions WHERE message_id = ? AND username = ? AND emoji = ?",
                (msg_id, me, body.emoji),
            )
        else:
            conn.execute(
                "INSERT INTO reactions(message_id, username, emoji) VALUES (?, ?, ?)",
                (msg_id, me, body.emoji),
            )
        conn.commit()
        reactions = reactions_for(conn, [msg_id]).get(msg_id, {})
    payload = {"type": "reaction", "id": msg_id, "reactions": reactions}
    if row["room"]:
        await send_to_room(row["room"], payload)
    else:
        await manager.send_to_users({row["sender"], row["recipient"]}, payload)
    return {"reactions": reactions}


def receipts_on(conn: sqlite3.Connection, username: str) -> bool:
    """Read receipts are ON unless the user switched them off."""
    row = conn.execute("SELECT read_receipts FROM profiles WHERE username = ?", (username,)).fetchone()
    return row is None or row["read_receipts"] is None or row["read_receipts"] != 0


def mark_dm_read(conn: sqlite3.Connection, me: str, partner: str):
    """Mark messages `partner` sent to `me` as read. Returns (ids, ts).
    Like WhatsApp, nothing is marked unless BOTH people have read receipts on."""
    if not (receipts_on(conn, me) and receipts_on(conn, partner)):
        return [], None
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM messages WHERE room IS NULL AND sender = ? AND recipient = ? "
        "AND read_at IS NULL AND deleted = 0", (partner, me))]
    if not ids:
        return [], None
    ts = time.time()
    marks = ",".join("?" * len(ids))
    conn.execute(f"UPDATE messages SET read_at = ? WHERE id IN ({marks})", (ts, *ids))
    conn.commit()
    return ids, ts


class SettingsIn(BaseModel):
    read_receipts: bool


@app.get("/api/settings")
def get_settings(me: str = Depends(current_user)):
    with closing(db()) as conn:
        return {"read_receipts": receipts_on(conn, me)}


@app.post("/api/settings")
def update_settings(body: SettingsIn, me: str = Depends(current_user)):
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO profiles(username, read_receipts) VALUES (?, ?) "
            "ON CONFLICT(username) DO UPDATE SET read_receipts = excluded.read_receipts",
            (me, 1 if body.read_receipts else 0),
        )
        conn.commit()
    return {"read_receipts": body.read_receipts}


class ReadIn(BaseModel):
    partner: str


@app.post("/api/read")
async def mark_read(body: ReadIn, me: str = Depends(current_user)):
    """The current user has opened / is looking at the DM with `partner`."""
    with closing(db()) as conn:
        if not are_friends(conn, me, body.partner):
            raise HTTPException(403, "You can only read chats with friends")
        ids, ts = mark_dm_read(conn, me, body.partner)
    if ids:
        await manager.send_to_users({body.partner}, {"type": "messages_read", "by": me, "ids": ids, "read_at": ts})
    return {"marked": len(ids)}


def row_to_message(r: sqlite3.Row) -> dict:
    return {
        "type": "message",
        "id": r["id"],
        "kind": "room" if r["room"] else "dm",
        "room": r["room"],
        "sender": r["sender"],
        "recipient": r["recipient"],
        "content": r["content"],
        "ts": r["ts"],
        "edited_at": r["edited_at"],
        "deleted": bool(r["deleted"]),
        "reply_to": r["reply_to"],
        "read_at": r["read_at"],
    }


def _conv_clause(room, with_user, me):
    """SQL fragment + params selecting one conversation (a room or a DM pair)."""
    if room:
        return "room = ?", (room,)
    return (
        "room IS NULL AND ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))",
        (me, with_user, with_user, me),
    )


@app.get("/api/history")
def history(
    room: str | None = Query(default=None),
    with_user: str | None = Query(default=None, alias="with"),
    around: int | None = Query(default=None),
    me: str = Depends(current_user),
):
    with closing(db()) as conn:
        if room:
            if not can_access_room(conn, room, me):
                raise HTTPException(403, "You are not a member of this group")
        elif with_user:
            if not are_friends(conn, me, with_user):
                raise HTTPException(403, "You can only view chats with friends")
        else:
            raise HTTPException(400, "Provide 'room' or 'with'")
        clause, params = _conv_clause(room, with_user, me)
        if around is None:
            rows = conn.execute(
                f"SELECT * FROM messages WHERE {clause} ORDER BY id DESC LIMIT ?",
                (*params, HISTORY_LIMIT),
            ).fetchall()
            rows = list(reversed(rows))
        else:
            # a window of messages around one message (used when jumping to a search result)
            older = conn.execute(
                f"SELECT * FROM messages WHERE {clause} AND id <= ? ORDER BY id DESC LIMIT 40",
                (*params, around),
            ).fetchall()
            newer = conn.execute(
                f"SELECT * FROM messages WHERE {clause} AND id > ? ORDER BY id ASC LIMIT 40",
                (*params, around),
            ).fetchall()
            rows = list(reversed(older)) + list(newer)
    msgs = [row_to_message(r) for r in rows]
    with closing(db()) as conn:
        attach_extras(conn, msgs)
        show_receipts = bool(with_user) and not room and receipts_on(conn, me) and receipts_on(conn, with_user)
    for m in msgs:
        if not show_receipts or m["sender"] != me:
            m["read_at"] = None
    return msgs


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.get("/api/search")
def search_messages(
    q: str = Query(..., min_length=2, max_length=100),
    room: str | None = Query(default=None),
    with_user: str | None = Query(default=None, alias="with"),
    me: str = Depends(current_user),
):
    """Search text messages inside ONE conversation the user is allowed to see."""
    needle = q.strip()
    if len(needle) < 2:
        return []
    with closing(db()) as conn:
        if room:
            if not can_access_room(conn, room, me):
                raise HTTPException(403, "You are not a member of this group")
        elif with_user:
            if not are_friends(conn, me, with_user):
                raise HTTPException(403, "You can only search chats with friends")
        else:
            raise HTTPException(400, "Provide 'room' or 'with'")
        clause, params = _conv_clause(room, with_user, me)
        rows = conn.execute(
            f"SELECT id, sender, content, ts FROM messages WHERE {clause} AND deleted = 0 "
            "AND content NOT LIKE '/9j/%' AND content NOT LIKE 'iVBO%' "
            "AND content LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 50",
            (*params, "%" + _like_escape(needle) + "%"),
        ).fetchall()
    low = needle.lower()
    out = []
    for r in rows:
        text = r["content"]
        i = text.lower().find(low)
        start = max(0, i - 40) if i > 0 else 0
        out.append({
            "id": r["id"],
            "sender": r["sender"],
            "snippet": ("…" if start else "") + text[start:start + 160],
            "ts": r["ts"],
        })
    return out


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

    async def announce_presence(self) -> None:
        await self.broadcast({"type": "presence", "online": self.online_users()})


manager = ConnectionManager()

# ---------------------------------------------------------------- admin
# NOTE: import name must match your file name exactly (Admin.py -> Admin, admin.py -> admin)
from Admin import make_router  # noqa: E402

app.include_router(make_router(db, current_user, manager))
app.include_router(make_friends_router(db, current_user, manager))
app.include_router(make_groups_router(db, current_user, manager))


async def send_to_room(room: str, payload: dict) -> None:
    """Public room -> everybody. Private group -> members only."""
    with closing(db()) as conn:
        audience = room_audience(conn, room)
    if audience is None:
        await manager.broadcast(payload)
    else:
        await manager.send_to_users(audience, payload)


def save_message(room: str | None, sender: str, recipient: str | None, content: str,
                 reply_to: int | None = None) -> dict:
    ts = time.time()
    with closing(db()) as conn:
        cur = conn.execute(
            "INSERT INTO messages(room, sender, recipient, content, ts, reply_to) VALUES (?, ?, ?, ?, ?, ?)",
            (room, sender, recipient, content, ts, reply_to),
        )
        conn.commit()
        msg_id = cur.lastrowid
        reply = reply_preview(conn, reply_to) if reply_to else None
    return {
        "type": "message",
        "id": msg_id,
        "edited_at": None,
        "deleted": False,
        "read_at": None,
        "reply_to": reply_to,
        "reply": reply,
        "reactions": {},
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
            content = str(data.get("content", "")).strip()[:MAX_MESSAGE_LEN]
            kind = data.get("type")
            if not content and kind in ("room", "dm"):
                continue
            if kind == "typing":
                # Broadcast typing indicator
                target = str(data.get("target") or "")
                payload = {"type": "typing", "user": username, "target": target}
                if not target:
                    await manager.broadcast(payload)  # "stopped typing" signal
                else:
                    with closing(db()) as conn:
                        is_room = conn.execute("SELECT 1 FROM rooms WHERE name = ?", (target,)).fetchone() is not None
                        allowed = can_access_room(conn, target, username) if is_room else are_friends(conn, username, target)
                    if allowed:
                        if is_room:
                            await send_to_room(target, payload)
                        else:
                            await manager.send_to_users({target}, payload)
            elif kind == "room":
                room = str(data.get("room", ""))
                with closing(db()) as conn:
                    allowed = can_access_room(conn, room, username)
                    reply_to = valid_reply_id(conn, data.get("reply_to"), room, username, None) if allowed else None
                if not allowed:
                    continue
                await send_to_room(room, save_message(room, username, None, content, reply_to))
            elif kind == "dm":
                to = str(data.get("to", ""))
                with closing(db()) as conn:
                    allowed = are_friends(conn, username, to)
                    reply_to = valid_reply_id(conn, data.get("reply_to"), None, username, to) if allowed else None
                if not allowed:
                    await ws.send_text(json.dumps({"type": "error", "detail": "You can only message friends"}))
                    continue
                msg = save_message(None, username, to, content, reply_to)
                await manager.send_to_users({username, to}, msg)
            elif kind == "image":
                img_data = str(data.get("image", ""))
                if not img_data.startswith(("/9j/", "iVBO")) or len(img_data) > MAX_IMAGE_LEN:
                    continue
                room = data.get("room")
                to = data.get("to")
                if room:
                    with closing(db()) as conn:
                        ok = can_access_room(conn, str(room), username)
                    if ok:
                        await send_to_room(str(room), save_message(str(room), username, None, img_data))
                elif to:
                    with closing(db()) as conn:
                        ok = are_friends(conn, username, str(to))
                    if ok:
                        msg = save_message(None, username, str(to), img_data)
                        await manager.send_to_users({username, str(to)}, msg)
            elif kind == "edit":
                # Handle message edit
                msg_id = data.get("id")
                new_content = str(data.get("content", "")).strip()[:MAX_MESSAGE_LEN]
                if msg_id and new_content:
                    with closing(db()) as conn:
                        row = conn.execute("SELECT sender, room, recipient FROM messages WHERE id = ?", (msg_id,)).fetchone()
                        if row and row["sender"] == username:
                            edited_at = time.time()
                            conn.execute("UPDATE messages SET content = ?, edited_at = ? WHERE id = ?",
                                        (new_content, edited_at, msg_id))
                            conn.commit()
                            payload = {"type": "message_edited", "id": msg_id, "content": new_content, "edited_at": edited_at}
                            if row["room"]:
                                await send_to_room(row["room"], payload)
                            else:
                                await manager.send_to_users({username, row["recipient"]}, payload)
            elif kind == "delete":
                # Handle message delete
                msg_id = data.get("id")
                if msg_id:
                    with closing(db()) as conn:
                        row = conn.execute("SELECT sender, room, recipient FROM messages WHERE id = ?", (msg_id,)).fetchone()
                        if row and row["sender"] == username:
                            conn.execute("UPDATE messages SET deleted = 1 WHERE id = ?", (msg_id,))
                            conn.commit()
                            payload = {"type": "message_deleted", "id": msg_id}
                            if row["room"]:
                                await send_to_room(row["room"], payload)
                            else:
                                await manager.send_to_users({username, row["recipient"]}, payload)
    except WebSocketDisconnect:
        pass
    finally:
        manager.conns.pop(ws, None)
        await manager.announce_presence()


# ---------------------------------------------------------------- frontend
@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/service-worker.js")
def service_worker():
    # served from the site root so its scope covers the whole app
    return FileResponse(
        BASE_DIR / "static" / "service-worker.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


@app.get("/admin")
def admin_page():
    return FileResponse(BASE_DIR / "static" / "admin.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")