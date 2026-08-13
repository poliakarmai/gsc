import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import urllib.request, ipaddress
from urllib.parse import urlparse

SECRET = "TOP_SECRET_FLAG_12345"

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        return host.lower() not in ("localhost", "127.0.0.1", "0.0.0.0", "::1")

@app.route("/secret")
def secret():
    return jsonify({"secret": SECRET})

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # FIXED: блокировка loopback/private
    if not is_safe_url(url):
        return jsonify({"error": "blocked"}), 403
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
