import os
from flask import Flask, request, jsonify

app = Flask(__name__)

import io, xml.sax, xml.sax.handler

class Handler(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.content = []
    def characters(self, content):
        self.content.append(content)

@app.route("/parse", methods=["POST"])
def parse():
    data = request.get_data()
    handler = Handler()
    parser = xml.sax.make_parser()
    # VULNERABLE: включён резолвинг внешних сущностей
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    parser.setContentHandler(handler)
    try:
        parser.parse(io.BytesIO(data))
        return jsonify({"content": "".join(handler.content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
