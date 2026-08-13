import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

import sqlite3

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?,?,?)",
        [("alice", "pass123", "user"), ("admin", "s3cr3t", "admin")])
    conn.commit()
    return conn

@app.get("/login")
def login(request: Request):
    username = request.query_params.get("username", "")
    password = request.query_params.get("password", "")
    conn = get_db()
    # FIXED: параметризованный запрос
    rows = conn.execute("SELECT username, role FROM users WHERE username=? AND password=?",
                        (username, password)).fetchall()
    conn.close()
    if rows:
        return JSONResponse({"status": "ok", "user": rows[0][0], "role": rows[0][1]})
    return JSONResponse({"status": "fail"}, status_code=401)

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
