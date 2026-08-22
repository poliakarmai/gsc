"""GSC-01 parity: API and worker must apply the *same* target policy."""
import pytest

from gsc_cloud.server import _validate_target
from gsc_cloud.worker import validate_target


def test_api_and_worker_accept_same_allowlisted_hosts(monkeypatch):
    monkeypatch.setenv("GSC_ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org")
    for target in (
        "https://github.com/acme/repo.git",
        "https://gitlab.com/acme/repo.git",
        "https://bitbucket.org/acme/repo.git",
    ):
        _validate_target(target)   # no raise = accepted (HTTP 200 path)
        validate_target(target)    # no raise = accepted (worker dequeue path)


@pytest.mark.parametrize("target", [
    "http://github.com/acme/repo.git",
    "ssh://git@github.com/acme/repo.git",
    "git://github.com/acme/repo.git",
    "https://token:secret@github.com/acme/repo.git",
    "https://evil.com/acme/repo.git",
    "https://github.com",              # no repo path
])
def test_api_and_worker_reject_same_bad_targets(monkeypatch, target):
    monkeypatch.setenv("GSC_ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org")
    with pytest.raises(ValueError):
        validate_target(target)       # worker path → ValueError
    with pytest.raises(Exception) as excinfo:
        _validate_target(target)      # API path → HTTPException(400)
    assert getattr(excinfo.value, "status_code", None) == 400


def test_allowlist_is_configurable(monkeypatch):
    monkeypatch.setenv("GSC_ALLOWED_GIT_HOSTS", "gitlab.com")
    validate_target("https://gitlab.com/acme/repo.git")   # accepted
    with pytest.raises(ValueError):
        validate_target("https://github.com/acme/repo.git")  # now rejected
