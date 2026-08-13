import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # VULNERABLE: отражение без экранирования
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
