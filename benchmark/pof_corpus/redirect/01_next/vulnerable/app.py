import os
from flask import Flask, request, jsonify

app = Flask(__name__)

from flask import redirect

@app.route("/go")
def go():
    next_url = request.args.get("next", "/")
    # VULNERABLE: redirect на пользовательский URL без валидации
    return redirect(next_url)

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
