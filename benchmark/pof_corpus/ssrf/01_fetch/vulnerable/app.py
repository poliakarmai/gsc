import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import urllib.request

SECRET = "TOP_SECRET_FLAG_12345"

@app.route("/secret")
def secret():
    return jsonify({"secret": SECRET})

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # VULNERABLE: fetch произвольного URL без валидации
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
