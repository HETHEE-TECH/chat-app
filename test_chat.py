import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["CHAT_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

with TestClient(main.app) as client:
    # --- auth
    r = client.post("/api/register", json={"username": "alice", "password": "secret1"})
    assert r.status_code == 200, r.text
    alice = r.json()["token"]
    r = client.post("/api/register", json={"username": "bob", "password": "secret2"})
    bob = r.json()["token"]
    assert client.post("/api/register", json={"username": "alice", "password": "secret1"}).status_code == 409
    assert client.post("/api/register", json={"username": "x", "password": "secret1"}).status_code == 400
    assert client.post("/api/login", json={"username": "alice", "password": "wrong!!"}).status_code == 401
    assert client.post("/api/login", json={"username": "alice", "password": "secret1"}).status_code == 200
    print("auth ok")

    ha = {"Authorization": f"Bearer {alice}"}
    hb = {"Authorization": f"Bearer {bob}"}
    assert client.get("/api/rooms").status_code == 401

    # --- rooms and users
    assert client.get("/api/rooms", headers=ha).json() == ["general"]
    assert client.post("/api/rooms", headers=ha, json={"name": "Dev-Talk"}).status_code == 200
    assert client.post("/api/rooms", headers=ha, json={"name": "dev-talk"}).status_code == 409
    assert client.get("/api/rooms", headers=ha).json() == ["dev-talk", "general"]
    assert client.get("/api/users", headers=ha).json() == ["bob"]
    print("rooms/users ok")

    # --- websocket: bad token rejected
    try:
        with client.websocket_connect("/ws?token=nope"):
            raise AssertionError("bad token accepted")
    except Exception as e:  # starlette raises WebSocketDisconnect
        assert "AssertionError" not in type(e).__name__
    print("ws auth ok")

    # --- websocket: presence, room chat, DM
    with client.websocket_connect(f"/ws?token={alice}") as wa:
        p = wa.receive_json()
        assert p == {"type": "presence", "online": ["alice"]}, p
        with client.websocket_connect(f"/ws?token={bob}") as wb:
            assert wa.receive_json()["online"] == ["alice", "bob"]
            assert wb.receive_json()["online"] == ["alice", "bob"]

            wa.send_json({"type": "room", "room": "general", "content": "hello room"})
            for sock in (wa, wb):
                m = sock.receive_json()
                assert (m["kind"], m["room"], m["sender"], m["content"]) == ("room", "general", "alice", "hello room"), m

            wb.send_json({"type": "dm", "to": "alice", "content": "psst"})
            for sock in (wa, wb):
                m = sock.receive_json()
                assert (m["kind"], m["sender"], m["recipient"], m["content"]) == ("dm", "bob", "alice", "psst"), m

            # invalid messages are ignored (empty, unknown room, unknown user)
            wa.send_json({"type": "room", "room": "general", "content": "   "})
            wa.send_json({"type": "room", "room": "nope", "content": "x"})
            wa.send_json({"type": "dm", "to": "ghost", "content": "x"})
            wa.send_json({"type": "room", "room": "general", "content": "after junk"})
            m = wa.receive_json()
            assert m["content"] == "after junk", m
            wb.receive_json()
        assert wa.receive_json()["online"] == ["alice"]
    print("websocket ok")

    # --- history
    h = client.get("/api/history?room=general", headers=ha).json()
    assert [x["content"] for x in h] == ["hello room", "after junk"], h
    h = client.get("/api/history?with=bob", headers=ha).json()
    assert [x["content"] for x in h] == ["psst"], h
    h = client.get("/api/history?with=alice", headers=hb).json()
    assert [x["content"] for x in h] == ["psst"]
    assert client.get("/api/history", headers=ha).status_code == 400
    print("history ok")

    # --- frontend served
    r = client.get("/")
    assert r.status_code == 200 and "<title>Chat App</title>" in r.text
    print("frontend ok")

print("ALL TESTS PASSED")
