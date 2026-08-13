import os
from flask import Flask, request, jsonify

app = Flask(__name__)

from flask import render_template_string

@app.route("/render")
def render():
    name = request.args.get("name", "world")
    # VULNERABLE: пользовательский вход прямо в render_template_string
    return render_template_string(f"<h1>Hello, {name}!</h1>")

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
