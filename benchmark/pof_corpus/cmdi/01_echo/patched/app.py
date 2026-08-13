import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import re, subprocess

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIXED: валидация + subprocess со списком
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        return "invalid host", 400
    out = subprocess.run(["echo", host], capture_output=True, text=True).stdout
    return f"<pre>{out}</pre>"

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
