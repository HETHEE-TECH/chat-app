"""Friend system: send / accept / decline requests. DMs are allowed only between friends."""
import time
from contextlib import closing

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel


class UserRef(BaseModel):
    username: str


def ensure_table(db) -> None:
    with closing(db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS friendships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester TEXT NOT NULL,
                addressee TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                ts REAL NOT NULL,
                UNIQUE(requester, addressee)
            );
            CREATE INDEX IF NOT EXISTS idx_fr_addr ON friendships(addressee, status);
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocker TEXT NOT NULL,
                blocked TEXT NOT NULL,
                ts REAL NOT NULL,
                UNIQUE(blocker, blocked)
            );
            """
        )
        conn.commit()


def are_friends(conn, a: str, b: str) -> bool:
    row = conn.execute(
        """SELECT 1 FROM friendships
           WHERE status = 'accepted'
             AND ((requester = ? AND addressee = ?) OR (requester = ? AND addressee = ?))""",
        (a, b, b, a),
    ).fetchone()
    return row is not None


def make_router(db, current_user, manager) -> APIRouter:
    router = APIRouter(prefix="/api")

    async def notify(*names: str) -> None:
        await manager.send_to_users(set(names), {"type": "friends_updated"})

    @router.get("/users")
    def list_friends(me: str = Depends(current_user)):
        """Only accepted friends (this feeds the sidebar 'Friends' list)."""
        with closing(db()) as conn:
            rows = conn.execute(
                """SELECT CASE WHEN requester = ? THEN addressee ELSE requester END AS friend
                   FROM friendships
                   WHERE status = 'accepted' AND (requester = ? OR addressee = ?)
                   ORDER BY friend""",
                (me, me, me),
            ).fetchall()
        return [r["friend"] for r in rows]

    @router.get("/friends/requests")
    def list_requests(me: str = Depends(current_user)):
        with closing(db()) as conn:
            incoming = conn.execute(
                "SELECT requester FROM friendships WHERE addressee = ? AND status = 'pending' ORDER BY ts",
                (me,),
            ).fetchall()
            outgoing = conn.execute(
                "SELECT addressee FROM friendships WHERE requester = ? AND status = 'pending' ORDER BY ts",
                (me,),
            ).fetchall()
        return {
            "incoming": [r["requester"] for r in incoming],
            "outgoing": [r["addressee"] for r in outgoing],
        }

    @router.post("/friends/request")
    async def send_request(body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ? COLLATE NOCASE", (body.username.strip(),)
            ).fetchone()
            if not row:
                raise HTTPException(404, "User not found")
            other = row["username"]
            if other == me:
                raise HTTPException(400, "You cannot add yourself")

            if conn.execute("SELECT 1 FROM blocks WHERE blocker = ? AND blocked = ?", (me, other)).fetchone():
                raise HTTPException(403, "You blocked this user. Unblock them first")
            if conn.execute("SELECT 1 FROM blocks WHERE blocker = ? AND blocked = ?", (other, me)).fetchone():
                raise HTTPException(403, "Unable to send a request to this user")

            existing = conn.execute(
                """SELECT requester, status FROM friendships
                   WHERE (requester = ? AND addressee = ?) OR (requester = ? AND addressee = ?)""",
                (me, other, other, me),
            ).fetchone()
            if existing:
                if existing["status"] == "accepted":
                    raise HTTPException(409, "You are already friends")
                if existing["requester"] == me:
                    raise HTTPException(409, "Friend request already sent")
                # they already requested me -> accept automatically
                conn.execute(
                    "UPDATE friendships SET status = 'accepted' WHERE requester = ? AND addressee = ?",
                    (other, me),
                )
                conn.commit()
                accepted = True
            else:
                conn.execute(
                    "INSERT INTO friendships(requester, addressee, status, ts) VALUES (?, ?, 'pending', ?)",
                    (me, other, time.time()),
                )
                conn.commit()
                accepted = False
        await notify(me, other)
        return {"success": True, "accepted": accepted, "username": other}

    @router.post("/friends/accept")
    async def accept_request(body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            cur = conn.execute(
                "UPDATE friendships SET status = 'accepted' "
                "WHERE requester = ? AND addressee = ? AND status = 'pending'",
                (body.username, me),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(404, "No pending request from this user")
        await notify(me, body.username)
        return {"success": True}

    @router.post("/friends/decline")
    async def decline_request(body: UserRef, me: str = Depends(current_user)):
        """Decline an incoming request, or cancel one you sent."""
        with closing(db()) as conn:
            conn.execute(
                """DELETE FROM friendships
                   WHERE status = 'pending'
                     AND ((requester = ? AND addressee = ?) OR (requester = ? AND addressee = ?))""",
                (body.username, me, me, body.username),
            )
            conn.commit()
        await notify(me, body.username)
        return {"success": True}

    @router.delete("/friends/{username}")
    async def unfriend(username: str, me: str = Depends(current_user)):
        with closing(db()) as conn:
            conn.execute(
                """DELETE FROM friendships
                   WHERE status = 'accepted'
                     AND ((requester = ? AND addressee = ?) OR (requester = ? AND addressee = ?))""",
                (username, me, me, username),
            )
            conn.commit()
        await notify(me, username)
        return {"success": True}

    @router.get("/friends/blocked")
    def list_blocked(me: str = Depends(current_user)):
        with closing(db()) as conn:
            rows = conn.execute(
                "SELECT blocked FROM blocks WHERE blocker = ? ORDER BY blocked", (me,)
            ).fetchall()
        return [r["blocked"] for r in rows]

    @router.post("/friends/block")
    async def block_user(body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ? COLLATE NOCASE", (body.username.strip(),)
            ).fetchone()
            if not row:
                raise HTTPException(404, "User not found")
            other = row["username"]
            if other == me:
                raise HTTPException(400, "You cannot block yourself")
            # remove friendship / pending requests in both directions
            conn.execute(
                """DELETE FROM friendships
                   WHERE (requester = ? AND addressee = ?) OR (requester = ? AND addressee = ?)""",
                (me, other, other, me),
            )
            conn.execute(
                "INSERT OR IGNORE INTO blocks(blocker, blocked, ts) VALUES (?, ?, ?)",
                (me, other, time.time()),
            )
            conn.commit()
        await notify(me, other)
        return {"success": True, "username": other}

    @router.post("/friends/unblock")
    async def unblock_user(body: UserRef, me: str = Depends(current_user)):
        with closing(db()) as conn:
            conn.execute("DELETE FROM blocks WHERE blocker = ? AND blocked = ?", (me, body.username))
            conn.commit()
        await notify(me)
        return {"success": True}

    return router