"""Tests for TAXII discovery flow (gsc_taxii_export.discover_collection_url)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from gsc_cli.gsc_taxii_export import discover_collection_url, _pick


def _discovery_response(port):
    return {"title": "TAXII", "api_roots": [f"http://127.0.0.1:{port}/api1/"]}


def _api_root_response(port):
    return {"title": "root", "collections": [
        f"http://127.0.0.1:{port}/api1/collections/abc/",
        f"http://127.0.0.1:{port}/api1/collections/def/",
    ]}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.path.endswith("/taxii2/"):
            body = json.dumps(_discovery_response(port))
        elif self.path.endswith("/api1/"):
            body = json.dumps(_api_root_response(port))
        else:
            body = json.dumps({"id": "abc", "title": "Collection"})
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def taxii_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()


def test_discover_returns_first_collection(taxii_server):
    port = taxii_server
    url = discover_collection_url(f"http://127.0.0.1:{port}/taxii2/")
    assert url == f"http://127.0.0.1:{port}/api1/collections/abc/objects/"


def test_discover_picks_named_collection(taxii_server):
    port = taxii_server
    url = discover_collection_url(f"http://127.0.0.1:{port}/taxii2/", collection="def")
    assert url == f"http://127.0.0.1:{port}/api1/collections/def/objects/"


def test_pick_by_id_segment():
    items = ["http://h/api1/collections/abc/", "http://h/api1/collections/def/"]
    assert _pick(items, "abc", "collection") == "http://h/api1/collections/abc/"
    assert _pick(items, None, "collection") == items[0]


def test_pick_not_found_raises():
    with pytest.raises(RuntimeError):
        _pick(["http://h/a/"], "missing", "collection")


def test_pick_empty_list_raises():
    with pytest.raises(RuntimeError, match="no collections"):
        _pick([], None, "collection")


def test_pick_name_with_trailing_slash():
    items = ["http://h/api1/collections/abc/"]
    assert _pick(items, "abc/", "collection") == "http://h/api1/collections/abc/"
    assert _pick(items, "abc", "collection") == "http://h/api1/collections/abc/"


def _run_against(handler, fn):
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        return fn(f"http://127.0.0.1:{port}/taxii2/", port)
    finally:
        server.shutdown()


def test_discover_non_dict_json_raises():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(["not", "an", "object"]).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    with pytest.raises(RuntimeError, match="not a JSON object"):
        _run_against(H, lambda url, port: discover_collection_url(url))


def test_discover_non_list_collections_raises():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            port = self.server.server_address[1]
            if self.path.endswith("/taxii2/"):
                body = json.dumps({"api_roots": [f"http://127.0.0.1:{port}/api1/"]})
            else:
                body = json.dumps({"collections": "not-a-list"})
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *a): pass

    with pytest.raises(RuntimeError, match="no collections"):
        _run_against(H, lambda url, port: discover_collection_url(url))
