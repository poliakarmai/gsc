import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import json

@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    # FIXED: JSON вместо pickle
    try:
        obj = json.loads(data)
        return jsonify({"loaded": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
