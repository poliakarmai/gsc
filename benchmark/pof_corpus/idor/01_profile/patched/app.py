import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

from fastapi import HTTPException

USERS = {
    1: {"name": "alice", "email": "alice@ex.com", "token": "tok_alice"},
    2: {"name": "bob",   "email": "bob-secret@ex.com", "token": "tok_bob"},
}

@app.get("/profile/{user_id}")
def profile(user_id: int, token: str = ""):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    u = USERS[user_id]
    # FIXED: проверка, что token принадлежит запрашиваемому пользователю
    if token != u["token"]:
        raise HTTPException(status_code=403, detail="forbidden")
    return JSONResponse({"name": u["name"], "email": u["email"]})

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
