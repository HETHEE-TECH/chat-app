"""Private groups.

- Existing rooms (and 'general') stay PUBLIC: everybody sees them.
- New rooms created by users are PRIVATE groups: only members see them.
- A group owner can invite FRIENDS (the friend must accept) or share an invite code
  that lets anybody join by themselves.
"""
import re
import secrets
import sqlite3
import time
from contextlib import closing

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from friends import are_friends

NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")


class RoomIn(BaseModel):
    name: str


class UserRef(BaseModel):
    username: str


class RoomRef(BaseModel):
    room: str


class JoinIn(BaseModel):
    code: str


# ---------------------------------------------------------------- schema / helpers
def ensure_group_tables(db) -> None:
    with closing(db()) as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(rooms)")}
        if "is_public" not in cols:
            conn.execute("ALTER TABLE rooms ADD COLUMN is_public INTEGER DEFAULT 0")
            # every room that existed before groups were introduced stays public
            conn.execute("UPDATE rooms SET is_public = 1")
        if "owner" not in cols:
            conn.execute("ALTER TABLE rooms ADD COLUMN owner TEXT")
        if "invite_code" not in cols:
            conn.execute("ALTER TABLE rooms ADD COLUMN invite_code TEXT")
        conn.executescript(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_room_code ON rooms(invite_code);
            CREATE TABLE IF NOT EXISTS room_members (
                room TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                ts REAL NOT NULL,
                PRIMARY KEY (room, username)
            );
            CREATE TABLE IF NOT EXISTS room_invites (
                room TEXT NOT NULL,
                invitee TEXT NOT NULL,
                inviter TEXT NOT NULL,
                ts REAL NOT NULL,
                PRIMARY KEY (room, invitee)
            );
            """
        )
        conn.commit()


def _room(conn: sqlite3.Connection, name: str):
    row = conn.execute("SELECT * FROM rooms WHERE name = ?", (name,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    return row


def _role(conn: sqlite3.Connection, room: str, user: str):
    row = conn.execute(
        "SELECT role FROM room_members WHERE room = ? AND username = ?", (room, user)
    ).fetchone()
    return row["role"] if row else None


def _members(conn: sqlite3.Connection, room: str) -> list[str]:
    rows = conn.execute(
        "SELECT username FROM room_members WHERE room = ? ORDER BY ts", (room,)
    ).fetchall()
    return [r["username"] for r in rows]


def _delete_room(conn: sqlite3.Connection, name: str) -> None:
    conn.execute("DELETE FROM rooms WHERE name = ?", (name,))
    conn.execute("DELETE FROM room_members WHERE room = ?", (name,))
    conn.execute("DELETE FROM room_invites WHERE room = ?", (name,))
    conn.execute("UPDATE messages SET deleted = 1 WHERE room = ?", (name,))


def can_access_room(conn: sqlite3.Connection, room: str, user: str) -> bool:
    row = conn.execute("SELECT is_public FROM rooms WHERE name = ?", (room,)).fetchone()
    if not row:
        return False
    if row["is_public"]:
        return True
    return _role(conn, room, user) is not None


def room_audience(conn: sqlite3.Connection, room: str):
    """None = public room (everybody). Otherwise the set of member usernames."""
    row = conn.execute("SELECT is_public FROM rooms WHERE name = ?", (room,)).fetchone()
    if not row:
        return set()
    if row["is_public"]:
        return None
    return set(_members(conn, room))


def cleanup_user(conn: sqlite3.Connection, username: str) -> None:
    """Call when an account is deleted (admin panel)."""
    conn.execute("DELETE FROM room_invites WHERE invitee = ? OR inviter = ?", (username, username))
    owned = [
        r["room"]
        for r in conn.execute(
            "SELECT room FROM room_members WHERE username = ? AND role = 'owner'", (username,)
        )
    ]
    conn.execute("DELETE FROM room_members WHERE username = ?", (username,))
    for room in owned:
        remaining = _members(conn, room)
        if not remaining:
            _delete_room(conn, room)
        else:
            conn.execute(
                "UPDATE room_members SET role = 'owner' WHERE room = ? AND username = ?",
                (room, remaining[0]),
            )
            conn.execute("UPDATE rooms SET owner = ? WHERE name = ?", (remaining[0], room))


# ---------------------------------------------------------------- routes
def make_router(db, current_user, manager) -> APIRouter:
    router = APIRouter(prefix="/api")

    async def notify(users) -> None:
        await manager.send_to_users(set(users), {"type": "groups_updated"})

    @router.get("/rooms")
    def list_rooms(me: str = Depends(current_user)):
        with closing(db()) as conn:
            rows = conn.execute(
                """SELECT r.name, r.is_public, m.role
                   FROM rooms r
                   LEFT JOIN room_members m ON m.room = r.name AND m.username = ?
                   WHERE r.is_public = 1 OR m.username IS NOT NULL
                   ORDER BY r.is_public DESC, r.name""",
                (me,),
            ).fetchall()
        return [{"name": r["name"], "is_public": bool(r["is_public"]), "role": r["role"]} for r in rows]

    @router.post("/rooms")
    async def create_group(room: RoomIn, me: str = Depends(current_user)):
        name = room.name.strip().lower()
        if not NAME_RE.match(name):
            raise HTTPException(400, "Group name must be 3-20 letters, numbers, _ or -")
        with closing(db()) as conn:
            try:
                conn.execute(
                    "INSERT INTO rooms(name, is_public, owner, invite_code) VALUES (?, 0, ?, ?)",
                    (name, me, secrets.token_urlsafe(6)),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "A group with this name already exists")
            conn.execute(
                "INSERT INTO room_members(room, username, role, ts) VALUES (?, ?, 'owner', ?)",
                (name, me, time.time()),
            )
            conn.commit()
        await notify({me})
        return {"name": name}

    @router.get("/rooms/{name}/members")
    def group_members(name: str, me: str = Depends(current_user)):
        with closing(db()) as conn:
            room = _room(conn, name)
            if room["is_public"]:
                raise HTTPException(400, "This is a public room")
            role = _role(conn, name, me)
            if not role:
                raise HTTPException(403, "You are not a member of this group")
            rows = conn.execute(
                """SELECT username, role FROM room_members WHERE room = ?
                   ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END, ts""",
                (name,),
            ).fetchall()
            is_owner = role == "owner"
            invited = []
            if is_owner:
                invited = [
                    r["invitee"]
                    for r in conn.execute("SELECT invitee FROM room_invites WHERE room = ?", (name,))
                ]
        return {
            "name": name,
            "owner": room["owner"],
            "members": [{"username": r["username"], "role": r["role"]} for r in rows],
            "invited": invited,
            "invite_code": room["invite_code"] if is_owner else None,
        }

    # ---- invite a friend
    @router.post("/rooms/{name}/invite")
    async def invite_friend(name: str, body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            room = _room(conn, name)
            if room["is_public"]:
                raise HTTPException(400, "This is a public room")
            if _role(conn, name, me) != "owner":
                raise HTTPException(403, "Only the group owner can invite people")
            row = conn.execute(
                "SELECT username FROM users WHERE username = ? COLLATE NOCASE", (body.username.strip(),)
            ).fetchone()
            if not row:
                raise HTTPException(404, "User not found")
            other = row["username"]
            if not are_friends(conn, me, other):
                raise HTTPException(403, "You can only invite your friends")
            if _role(conn, name, other):
                raise HTTPException(409, "Already a member")
            if conn.execute(
                "SELECT 1 FROM room_invites WHERE room = ? AND invitee = ?", (name, other)
            ).fetchone():
                raise HTTPException(409, "Already invited")
            conn.execute(
                "INSERT INTO room_invites(room, invitee, inviter, ts) VALUES (?, ?, ?, ?)",
                (name, other, me, time.time()),
            )
            conn.commit()
        await notify({me, other})
        return {"success": True}

    @router.get("/group-invites")
    def my_invites(me: str = Depends(current_user)):
        with closing(db()) as conn:
            rows = conn.execute(
                """SELECT i.room, i.inviter FROM room_invites i
                   JOIN rooms r ON r.name = i.room
                   WHERE i.invitee = ? ORDER BY i.ts""",
                (me,),
            ).fetchall()
        return [{"room": r["room"], "inviter": r["inviter"]} for r in rows]

    @router.post("/group-invites/accept")
    async def accept_invite(body: RoomRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            inv = conn.execute(
                "SELECT 1 FROM room_invites WHERE room = ? AND invitee = ?", (body.room, me)
            ).fetchone()
            if not inv:
                raise HTTPException(404, "Invitation not found")
            exists = conn.execute("SELECT 1 FROM rooms WHERE name = ?", (body.room,)).fetchone()
            conn.execute("DELETE FROM room_invites WHERE room = ? AND invitee = ?", (body.room, me))
            if not exists:
                conn.commit()
                raise HTTPException(404, "This group no longer exists")
            conn.execute(
                "INSERT OR IGNORE INTO room_members(room, username, role, ts) VALUES (?, ?, 'member', ?)",
                (body.room, me, time.time()),
            )
            conn.commit()
            audience = set(_members(conn, body.room))
        await notify(audience | {me})
        return {"success": True, "name": body.room}

    @router.post("/group-invites/decline")
    async def decline_invite(body: RoomRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            conn.execute("DELETE FROM room_invites WHERE room = ? AND invitee = ?", (body.room, me))
            conn.commit()
            audience = set(_members(conn, body.room))
        await notify(audience | {me})
        return {"success": True}

    # ---- join with an invite code
    @router.post("/rooms/join")
    async def join_with_code(body: JoinIn, me: str = Depends(current_user)):
        code = body.code.strip()
        with closing(db()) as conn:
            row = None
            if code:
                row = conn.execute(
                    "SELECT name FROM rooms WHERE invite_code = ? AND is_public = 0", (code,)
                ).fetchone()
            if not row:
                raise HTTPException(404, "Invalid invite code")
            name = row["name"]
            if _role(conn, name, me):
                raise HTTPException(409, "You are already in this group")
            conn.execute(
                "INSERT INTO room_members(room, username, role, ts) VALUES (?, ?, 'member', ?)",
                (name, me, time.time()),
            )
            conn.execute("DELETE FROM room_invites WHERE room = ? AND invitee = ?", (name, me))
            conn.commit()
            audience = set(_members(conn, name))
        await notify(audience)
        return {"name": name}

    # ---- owner tools
    @router.post("/rooms/{name}/regenerate-code")
    def regenerate_code(name: str, me: str = Depends(current_user)):
        with closing(db()) as conn:
            _room(conn, name)
            if _role(conn, name, me) != "owner":
                raise HTTPException(403, "Only the group owner can do this")
            code = secrets.token_urlsafe(6)
            conn.execute("UPDATE rooms SET invite_code = ? WHERE name = ?", (code, name))
            conn.commit()
        return {"invite_code": code}

    @router.post("/rooms/{name}/kick")
    async def kick_member(name: str, body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            _room(conn, name)
            if _role(conn, name, me) != "owner":
                raise HTTPException(403, "Only the group owner can remove members")
            if body.username == me:
                raise HTTPException(400, "Use 'Leave group' to leave")
            if not _role(conn, name, body.username):
                raise HTTPException(404, "This user is not in the group")
            conn.execute(
                "DELETE FROM room_members WHERE room = ? AND username = ?", (name, body.username)
            )
            conn.commit()
            audience = set(_members(conn, name))
        await notify(audience | {body.username})
        return {"success": True}

    @router.post("/rooms/{name}/leave")
    async def leave_group(name: str, me: str = Depends(current_user)):
        with closing(db()) as conn:
            room = _room(conn, name)
            if room["is_public"]:
                raise HTTPException(400, "You cannot leave a public room")
            role = _role(conn, name, me)
            if not role:
                raise HTTPException(403, "You are not a member of this group")
            conn.execute("DELETE FROM room_members WHERE room = ? AND username = ?", (name, me))
            remaining = _members(conn, name)
            if not remaining:
                _delete_room(conn, name)
            elif role == "owner":
                conn.execute(
                    "UPDATE room_members SET role = 'owner' WHERE room = ? AND username = ?",
                    (name, remaining[0]),
                )
                conn.execute("UPDATE rooms SET owner = ? WHERE name = ?", (remaining[0], name))
            conn.commit()
        await notify(set(remaining) | {me})
        return {"success": True}

    @router.delete("/rooms/{name}")
    async def delete_group(name: str, me: str = Depends(current_user)):
        with closing(db()) as conn:
            room = _room(conn, name)
            if room["is_public"]:
                raise HTTPException(403, "Public rooms cannot be deleted")
            if _role(conn, name, me) != "owner":
                raise HTTPException(403, "Only the group owner can delete the group")
            audience = set(_members(conn, name))
            _delete_room(conn, name)
            conn.commit()
        await notify(audience)
        return {"success": True}

    return router