"""Tests for GSC TAXII ingest (gsc_taxii_ingest)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from gsc_cli.gsc_taxii_ingest import fetch_objects, stix_to_findings, taxii_ingest

_TS = "2026-08-23T00:00:00.000Z"


def _indicator(name="Malicious IP", labels=None):
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": "indicator--11111111-1111-1111-1111-111111111111",
        "created": _TS, "modified": _TS, "name": name,
        "pattern": "[ipv4-addr:value = '1.2.3.4']", "pattern_type": "stix",
        "valid_from": _TS, "labels": labels or [],
    }


def _vulnerability(cvss=None):
    obj = {
        "type": "vulnerability", "spec_version": "2.1",
        "id": "vulnerability--22222222-2222-2222-2222-222222222222",
        "created": _TS, "modified": _TS, "name": "CVE-2021-44228",
    }
    if cvss is not None:
        obj["external_references"] = [{"source_name": "cve", "external_id": "CVE-2021-44228",
                                       "x_cvss_score": cvss}]
    return obj


def test_indicator_maps_to_gioc():
    findings = stix_to_findings([_indicator(labels=["malicious-activity"])])
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "GIOC"
    assert f["severity"] == "HIGH"
    assert f["category"] == "external-intel"
    assert f["stix_id"].startswith("indicator--")


def test_indicator_default_severity_medium():
    findings = stix_to_findings([_indicator()])
    assert findings[0]["severity"] == "MEDIUM"


def test_vulnerability_cvss_maps_severity():
    findings = stix_to_findings([_vulnerability(cvss=10.0)])
    f = findings[0]
    assert f["rule_id"] == "GVULN"
    assert f["severity"] == "CRITICAL"
    assert f["cve"] == "CVE-2021-44228"


def test_vulnerability_without_cvss_defaults_medium():
    findings = stix_to_findings([_vulnerability()])
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["cve"] == ""


def test_skips_unsupported_types():
    objects = [{"type": "report", "name": "r"}, {"type": "observed-data", "id": "x"}]
    assert stix_to_findings(objects) == []


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        objects = [
            _indicator(labels=["malicious-activity"]),
            _vulnerability(cvss=9.5),
            {"type": "report", "name": "container"},
        ]
        body = json.dumps({"more": False, "objects": objects}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def taxii_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/api1/collections/abc/objects/"
    server.shutdown()


def test_fetch_objects_returns_list(taxii_server):
    objects = fetch_objects(taxii_server)
    assert len(objects) == 3
    assert objects[0]["type"] == "indicator"


def test_ingest_end_to_end(tmp_path, taxii_server):
    out = tmp_path / "findings.json"
    assert taxii_ingest(taxii_server, output=str(out)) == 0
    report = json.loads(Path(out).read_text(encoding="utf-8"))
    findings = report["findings"]
    assert len(findings) == 2  # indicator + vulnerability (report skipped)
    assert {f["rule_id"] for f in findings} == {"GIOC", "GVULN"}
