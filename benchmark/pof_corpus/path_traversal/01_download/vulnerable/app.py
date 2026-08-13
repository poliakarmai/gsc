import os
from flask import Flask, request, jsonify

app = Flask(__name__)

from flask import send_file, abort

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
os.makedirs(FILES_DIR, exist_ok=True)
with open(os.path.join(FILES_DIR, "public.txt"), "w") as f:
    f.write("public content")

@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # VULNERABLE: конкатенация пути без санитизации
    filepath = os.path.join(FILES_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath)

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
