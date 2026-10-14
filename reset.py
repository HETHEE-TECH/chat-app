import sqlite3, secrets, hashlib

USERNAME = "admin"
NEW_PASSWORD = "MyNewPass123"   # unga pudhu password

salt = secrets.token_bytes(16)
pw_hash = hashlib.pbkdf2_hmac("sha256", NEW_PASSWORD.encode(), salt, 200_000)

conn = sqlite3.connect("chat.db")
cur = conn.execute(
    "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
    (salt, pw_hash, USERNAME),
)
conn.commit()
print("Updated rows:", cur.rowcount)   # 1 vandha success, 0 na username illa