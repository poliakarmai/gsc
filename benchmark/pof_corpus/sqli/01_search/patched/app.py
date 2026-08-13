import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import sqlite3

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, email TEXT, is_admin INTEGER)")
    conn.executemany("INSERT INTO users VALUES (?,?,?)",
        [("alice","alice@ex.com",0),("bob","bob@ex.com",0),("root","root@ex.com",1)])
    conn.commit()
    return conn

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    # FIXED: параметризованный запрос
    rows = conn.execute("SELECT name,email FROM users WHERE name LIKE ?",
                        (f"%{q}%",)).fetchall()
    conn.close()
    return jsonify([{"name": r[0], "email": r[1]} for r in rows])

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
