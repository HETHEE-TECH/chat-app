import sqlite3

db = sqlite3.connect("chat.db")
cursor = db.cursor()

accounts = ["Hell", "Heya", "hethee"]

for account in accounts:
    cursor.execute("DELETE FROM users WHERE username = ?", (account,))
    cursor.execute("DELETE FROM tokens WHERE username = ?", (account,))
    cursor.execute("DELETE FROM messages WHERE sender = ? OR recipient = ?", (account, account))
    print(f"Deleted: {account}")

db.commit()
db.close()
print("Done! Accounts deleted.")