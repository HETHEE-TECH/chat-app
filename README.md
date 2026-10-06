# Chat App

A small real-time chat app built with Python (FastAPI + WebSockets) and a plain HTML/JS frontend.

## Features

- Sign up and log in (passwords hashed with PBKDF2, session tokens stored in SQLite)
- Group chat rooms (a `general` room exists by default; anyone can create more)
- Private 1-to-1 messages
- Saved message history (last 100 messages per conversation)
- Online/offline indicators and unread markers
- Auto-reconnect if the connection drops

## Run it

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://localhost:8000 in two browser windows (or one normal and one private window), create two accounts, and start chatting.

To let other devices on your network join, run `uvicorn main:app --host 0.0.0.0` and open `http://<your-computer-ip>:8000`.

## Project layout

```
main.py            FastAPI backend: auth, REST endpoints, WebSocket, SQLite storage
static/index.html  Frontend (single page, no build step)
requirements.txt   Python dependencies
test_chat.py       End-to-end test script (see below)
chat.db            Created automatically on first run
```

## How it works

REST endpoints (all except register/login need the header `Authorization: Bearer <token>`):

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/register` | Create account, returns a token |
| POST | `/api/login` | Log in, returns a token |
| GET | `/api/rooms` | List rooms |
| POST | `/api/rooms` | Create a room |
| GET | `/api/users` | List other users |
| GET | `/api/history?room=NAME` or `?with=USER` | Recent messages |

WebSocket: connect to `/ws?token=<token>`.

- Send `{"type": "room", "room": "general", "content": "hi"}` for a room message
- Send `{"type": "dm", "to": "bob", "content": "hi"}` for a private message
- Receive `{"type": "message", ...}`, `{"type": "presence", "online": [...]}` and `{"type": "room_created", "room": "..."}`

## Tests

```bash
pip install httpx
python test_chat.py
```

It uses a temporary database and covers registration, login, rooms, room chat, private chat, presence, history and the served frontend.

## Before putting it on the internet

This is a solid starting point, not a hardened production service. Things to add first:

- Serve it over HTTPS (so tokens and passwords are encrypted in transit)
- Add token expiry and rate limiting on login
- Move to PostgreSQL and a shared pub/sub (such as Redis) if you run more than one server process
- Make rooms private/invite-only if you need that (all rooms are public right now)
