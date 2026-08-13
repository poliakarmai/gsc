import os
from flask import Flask, request, jsonify

app = Flask(__name__)

from flask import redirect
from urllib.parse import urlparse

@app.route("/go")
def go():
    next_url = request.args.get("next", "/")
    # FIXED: разрешены только относительные URL
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        next_url = "/"
    return redirect(next_url)

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
