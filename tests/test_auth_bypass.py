"""tests/test_auth_bypass.py — GSC roadmap 6.4: auth-bypass regression.

Проверяет, что защищённые endpoints отклоняют запросы без/с невалидным API key
(401), а не отдают данные (unauthorized / IDOR). Запускается в subprocess, чтобы
изолировать module-level state server.py.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parent.parent)

PROBE = (
    "import os\n"
    "os.environ['GSC_DB'] = {db!r}\n"
    "os.environ['GSC_DEV_MODE'] = '1'\n"
    "import server\n"
    "server.init_cloud_db()\n"
    "from fastapi.testclient import TestClient\n"
    "c = TestClient(server.app)\n"
    "print(c.get('/api/v2/findings').status_code)\n"
    "print(c.get('/api/v2/scans', headers={{'X-API-Key': 'bogus'}}).status_code)\n"
    "print(c.get('/api/v2/stats').status_code)\n"
    "print(c.get('/api/v2/scans', headers={{'Authorization': 'Bearer deadbeef'}}).status_code)\n"
)


def test_protected_endpoints_require_auth(tmp_path):
    code = PROBE.format(db=str(tmp_path / "auth.db"))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO)
    codes = [int(x) for x in r.stdout.split() if x.strip().isdigit()]
    assert codes == [401, 401, 401, 401], f"expected all 401, got {codes!r}, stderr={r.stderr[-500:]!r}"


def test_signup_is_open_by_default_but_scan_requires_key(tmp_path):
    """Open signup OK, но /scan и /findings всё равно требуют валидный ключ."""
    code = (
        "import os\n"
        f"os.environ['GSC_DB'] = {str(tmp_path / 's.db')!r}\n"
        "os.environ['GSC_DEV_MODE'] = '1'\n"
        "import server\n"
        "server.init_cloud_db()\n"
        "from fastapi.testclient import TestClient\n"
        "c = TestClient(server.app)\n"
        "s = c.post('/api/v2/auth/signup', params={'github_user': 'x'})\n"
        "key = s.json().get('api_key', '')\n"
        "ok = c.get('/api/v2/findings', headers={'X-API-Key': key}).status_code\n"
        "bad = c.get('/api/v2/findings', headers={'X-API-Key': 'gsk_wrong'}).status_code\n"
        "print(s.status_code, ok, bad)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO)
    codes = [int(x) for x in r.stdout.split() if x.strip().isdigit()]
    assert codes == [200, 200, 401], f"expected [200,200,401], got {codes!r}, stderr={r.stderr[-500:]!r}"
