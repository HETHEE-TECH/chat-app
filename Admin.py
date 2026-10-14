"""Admin API for the chat app.

Admins are defined by the ADMIN_USERS env var (comma separated, default: "admin").
Register those usernames yourself BEFORE exposing the app, so nobody else can claim them.
"""
import hashlib
import os
import secrets
import sqlite3
import tempfile
import time
from contextlib import closing

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from groups import cleanup_user

ADMINS = {u.strip() for u in os.environ.get("ADMIN_USERS", "admin").split(",") if u.strip()}
PROTECTED_ROOMS = {"general"}  # the admin panel will not delete these


def make_router(db, current_user, manager) -> APIRouter:
    router = APIRouter(prefix="/api/admin")

    def admin_only(me: str = Depends(current_user)) -> str:
        if me not in ADMINS:
            raise HTTPException(403, "Admin access only")
        return me

    # ------------------------------------------------------------ users
    @router.get("/users")
    def list_users(_: str = Depends(admin_only)):
        online = set(manager.online_users())
        with closing(db()) as conn:
            rows = conn.execute(
                """SELECT u.id, u.username,
                          COALESCE(p.bio, '') AS bio,
                          COALESCE(p.avatar, '') AS avatar,
                          u.last_seen AS last_online,
                          (SELECT COUNT(*) FROM messages m
                            WHERE m.sender = u.username AND m.deleted = 0) AS msg_count,
                          (SELECT MAX(ts) FROM messages m
                            WHERE m.sender = u.username) AS last_ts
                   FROM users u
                   LEFT JOIN profiles p ON p.username = u.username
                   ORDER BY u.id"""
            ).fetchall()
        return [
            {
                "id": r["id"],
                "username": r["username"],
                "bio": r["bio"],
                "avatar": r["avatar"],
                "msg_count": r["msg_count"],
                "last_message_ts": r["last_ts"],
                "last_online": r["last_online"],
                "online": r["username"] in online,
                "is_admin": r["username"] in ADMINS,
            }
            for r in rows
        ]

    @router.delete("/users/{username}")
    async def delete_user(username: str, _: str = Depends(admin_only)):
        if username in ADMINS:
            raise HTTPException(400, "Admin accounts cannot be deleted")
        with closing(db()) as conn:
            if not conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise HTTPException(404, "User not found")
            msg_ids = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM messages WHERE sender = ? AND deleted = 0", (username,)
                )
            ]
            conn.execute("DELETE FROM tokens WHERE username = ?", (username,))
            conn.execute("DELETE FROM profiles WHERE username = ?", (username,))
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.execute("DELETE FROM friendships WHERE requester = ? OR addressee = ?", (username, username))
            conn.execute("DELETE FROM blocks WHERE blocker = ? OR blocked = ?", (username, username))
            conn.execute("DELETE FROM reactions WHERE username = ?", (username,))
            cleanup_user(conn, username)  # group memberships / invites / owned groups
            conn.execute("DELETE FROM voice_notes WHERE message_id IN (SELECT id FROM messages WHERE sender = ?)", (username,))
            # hide their messages (and DMs sent to them)
            conn.execute(
                "UPDATE messages SET deleted = 1 "
                "WHERE sender = ? OR (room IS NULL AND recipient = ?)",
                (username, username),
            )
            conn.commit()

        # kick any live connections
        for ws, name in list(manager.conns.items()):
            if name == username:
                manager.conns.pop(ws, None)
                try:
                    await ws.close(code=4401)
                except Exception:
                    pass

        for mid in msg_ids:
            await manager.broadcast({"type": "message_deleted", "id": mid})
        await manager.broadcast({"type": "friends_updated"})
        await manager.broadcast({"type": "groups_updated"})
        await manager.announce_presence()
        return {"success": True}

    @router.post("/users/{username}/reset-password")
    async def reset_password(username: str, _: str = Depends(admin_only)):
        """Set a random temporary password (for users who forgot theirs)."""
        if username in ADMINS:
            raise HTTPException(400, "Admin accounts cannot be reset here")
        temp = secrets.token_urlsafe(6)
        salt = secrets.token_bytes(16)
        # same algorithm / iterations as hash_password() in main.py
        pw_hash = hashlib.pbkdf2_hmac("sha256", temp.encode(), salt, 200_000)
        with closing(db()) as conn:
            if not conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise HTTPException(404, "User not found")
            conn.execute(
                "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
                (salt, pw_hash, username),
            )
            conn.execute("DELETE FROM tokens WHERE username = ?", (username,))  # force re-login
            conn.commit()
        for ws, name in list(manager.conns.items()):
            if name == username:
                manager.conns.pop(ws, None)
                try:
                    await ws.close(code=4401)
                except Exception:
                    pass
        await manager.announce_presence()
        return {"username": username, "temp_password": temp}

    @router.get("/backup")
    def download_backup(_: str = Depends(admin_only)):
        """A consistent copy of the whole database (users, messages, groups ...)."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        src = db()
        dst = sqlite3.connect(path)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename="chat-backup-" + time.strftime("%Y%m%d-%H%M") + ".db",
            background=BackgroundTask(os.remove, path),
        )

    # ------------------------------------------------------------ rooms / groups
    @router.get("/rooms")
    def list_rooms(_: str = Depends(admin_only)):
        with closing(db()) as conn:
            rows = conn.execute(
                """SELECT r.name, r.is_public, r.owner,
                          (SELECT COUNT(*) FROM room_members m WHERE m.room = r.name) AS members,
                          (SELECT COUNT(*) FROM messages g
                            WHERE g.room = r.name AND g.deleted = 0) AS msg_count
                   FROM rooms r ORDER BY r.is_public DESC, r.name"""
            ).fetchall()
        return [
            {
                "name": r["name"],
                "is_public": bool(r["is_public"]),
                "owner": r["owner"],
                "members": r["members"],
                "msg_count": r["msg_count"],
                "protected": r["name"] in PROTECTED_ROOMS,
            }
            for r in rows
        ]

    @router.delete("/rooms/{name}")
    async def delete_room(name: str, _: str = Depends(admin_only)):
        if name in PROTECTED_ROOMS:
            raise HTTPException(400, "This room is protected and cannot be deleted")
        with closing(db()) as conn:
            if not conn.execute("SELECT 1 FROM rooms WHERE name = ?", (name,)).fetchone():
                raise HTTPException(404, "Room not found")
            conn.execute("DELETE FROM rooms WHERE name = ?", (name,))
            conn.execute("DELETE FROM room_members WHERE room = ?", (name,))
            conn.execute("DELETE FROM room_invites WHERE room = ?", (name,))
            conn.execute("DELETE FROM voice_notes WHERE message_id IN (SELECT id FROM messages WHERE room = ?)", (name,))
            conn.execute("UPDATE messages SET deleted = 1 WHERE room = ?", (name,))
            conn.commit()
        await manager.broadcast({"type": "groups_updated"})
        return {"success": True}

    return router