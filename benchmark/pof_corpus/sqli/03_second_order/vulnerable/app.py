import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import sqlite3

DB_PATH = os.environ.get("NOTES_DB", "/tmp/sqli_so.db")

def get_conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS users "
              "(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT)")
    return c

def reset_and_seed():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    c = get_conn()
    c.execute("INSERT INTO users (username, email) VALUES ('alice','alice@ex.com')")
    c.execute("INSERT INTO users (username, email) VALUES ('admin','admin-secret@ex.com')")
    c.commit(); c.close()

@app.route("/register", methods=["POST"])
def register():
    username = request.get_json(force=True).get("username", "")
    c = get_conn()
    try:
        c.execute("INSERT INTO users (username, email) VALUES (?, ?)", (username, "user@ex.com"))
        c.commit()
    except sqlite3.IntegrityError:
        pass
    c.close()
    return jsonify({"status": "registered"})

@app.route("/promote", methods=["POST"])
def promote():
    target = request.get_json(force=True).get("username", "")
    c = get_conn()
    row = c.execute("SELECT username FROM users WHERE username=?", (target,)).fetchone()
    if row:
        stored = row[0]
        # VULNERABLE: сохранённое значение используется без параметризации
        c.execute(f"UPDATE users SET email='pwned@ex.com' WHERE username='{stored}'")
        c.commit()
    c.close()
    return jsonify({"status": "promoted"})

@app.route("/users")
def users():
    c = get_conn()
    rows = c.execute("SELECT username, email FROM users").fetchall()
    c.close()
    return jsonify([{"username": r[0], "email": r[1]} for r in rows])

@app.route("/health")
def health():
    return "ok"

reset_and_seed()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
