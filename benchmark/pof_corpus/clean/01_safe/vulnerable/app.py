import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/add")
def add():
    a = int(request.args.get("a", 0)); b = int(request.args.get("b", 0))
    return jsonify({"result": a + b})

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
