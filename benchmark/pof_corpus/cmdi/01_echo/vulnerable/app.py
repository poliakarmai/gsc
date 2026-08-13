import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: shell с пользовательским вводом
    out = os.popen(f"echo {host}").read()
    return f"<pre>{out}</pre>"

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
