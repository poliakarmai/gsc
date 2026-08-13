import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

import sqlite3
from markupsafe import escape

@app.get("/search")
def search(request: Request):
    q = request.query_params.get("q", "")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS items (name TEXT)")
    conn.execute("INSERT INTO items VALUES ('hello')")
    rows = conn.execute("SELECT name FROM items WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    conn.close()
    return JSONResponse({"results": [escape(r[0]) for r in rows]})

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
