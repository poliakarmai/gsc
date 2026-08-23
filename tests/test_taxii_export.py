"""Tests for GSC TAXII export (gsc_taxii_export)."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from gsc_cli.gsc_taxii_export import export_taxii


class _Handler(BaseHTTPRequestHandler):
    received = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).received = {
            "path": self.path,
            "content_type": self.headers.get("Content-Type", ""),
            "auth": self.headers.get("Authorization", ""),
            "body": json.loads(body),
        }
        resp = json.dumps({"id": "status--1", "status": "complete"}).encode()
        self.send_response(202)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):
        pass


@pytest.fixture
def taxii_server():
    _Handler.received = None
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/api1/collections/abc/objects/"
    server.shutdown()


def _write_report(tmp_path, findings):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(report)


def test_dry_run_does_not_push(tmp_path, taxii_server):
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "s", "file_path": "a.py", "detail": "d"},
    ])
    out = tmp_path / "bundle.json"
    assert export_taxii(report, taxii_server, dry_run=True, output=str(out)) == 0
    assert Path(out).exists()
    assert _Handler.received is None  # nothing was pushed


def test_push_to_mock_server(tmp_path, taxii_server):
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "s", "file_path": "a.py", "detail": "d"},
    ])
    assert export_taxii(report, taxii_server, username="user", password="pass") == 0
    assert _Handler.received is not None
    assert _Handler.received["path"].endswith("/objects/")
    assert "taxii+json" in _Handler.received["content_type"]
    expected = "Basic " + base64.b64encode(b"user:pass").decode()
    assert _Handler.received["auth"] == expected
    body = _Handler.received["body"]
    assert body["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in body["objects"])


def test_api_key_auth(tmp_path, taxii_server):
    report = _write_report(tmp_path, [
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW",
         "title": "s", "file_path": "a.js", "detail": "d"},
    ])
    assert export_taxii(report, taxii_server, api_key="secret-token") == 0
    assert _Handler.received["auth"] == "Bearer secret-token"
