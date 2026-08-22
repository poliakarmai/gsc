"""GS045 — GitHub Actions CI/CD Security tests."""
from gsc_core.gsc_detectors.gs045_github_actions import GS045GitHubActionsDetector

D = GS045GitHubActionsDetector()


def _detect(content: str):
    return D.detect(".github/workflows/ci.yml", content)


def test_missing_permissions():
    fs = _detect(
        "name: CI\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
    )
    assert any(f["rule_id"] == "GS045-missing_permissions" for f in fs)


def test_permissions_present_no_flag():
    fs = _detect(
        "name: CI\non: push\npermissions: read-all\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    assert not any(f["rule_id"] == "GS045-missing_permissions" for f in fs)


def test_pr_target_checkout_head_critical():
    fs = _detect(
        "on:\n  pull_request_target:\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert any(f["rule_id"] == "GS045-pr_target_checkout_head" and f["severity"] == "CRITICAL" for f in fs)


def test_hardcoded_env_secret():
    fs = _detect(
        "name: CI\non: push\npermissions: read-all\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    env:\n      API_KEY: \"sk_live_1234567890\"\n"
        "    steps:\n      - run: echo hi\n"
    )
    assert any(f["rule_id"] == "GS045-hardcoded_env_secret" for f in fs)
