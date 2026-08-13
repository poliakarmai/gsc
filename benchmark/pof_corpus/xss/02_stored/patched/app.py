import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

from fastapi import Form
from fastapi.responses import HTMLResponse
from markupsafe import escape

COMMENTS = []

@app.post("/comment")
def add_comment(text: str = Form(...)):
    COMMENTS.append(text)
    return {"status": "saved"}

@app.get("/board", response_class=HTMLResponse)
def board():
    # FIXED: экранирование на выводе
    items = "".join(f"<li>{escape(c)}</li>" for c in COMMENTS)
    return f"<html><body><ul>{items}</ul></body></html>"

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
