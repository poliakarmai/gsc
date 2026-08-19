"""GSC-05: billing checkout must enforce owner/security role.

Regression for the due-diligence finding where checkout ignored ``user_id``
(queried ``memberships`` with ``(None, tid)``) and let any member reach
``create_checkout``.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# SaaS deps (stripe, fastapi) are intentionally not in requirements-dev.txt —
# S1-S4 are not implemented yet. Skip cleanly on bare CI; the test still runs
# locally where those deps are installed.
pytest.importorskip("stripe")
pytest.importorskip("fastapi")

from fastapi import HTTPException


def _call_checkout(fetchone_result):
    from gsc_cloud import billing as billing_mod

    db = MagicMock()
    db.fetchone.return_value = fetchone_result
    req = MagicMock()

    with patch("gsc_cloud.dash_api._ctx", return_value=(100, 7)), \
         patch("gsc_cloud.billing.control_plane", return_value=db) as cp, \
         patch("gsc_cloud.billing.create_checkout", return_value="https://checkout") as cc:
        try:
            result = billing_mod.checkout(req, {"plan": "business", "seats": 3})
        except HTTPException as e:
            return e, cp, db, cc
        return result, cp, db, cc


def test_checkout_rejects_developer_role():
    err, _cp, db, cc = _call_checkout({"role": "developer"})
    assert isinstance(err, HTTPException)
    assert err.status_code == 403
    # role query must be scoped to the real user, not None
    assert db.fetchone.call_args[0][1][0] == 100
    cc.assert_not_called()


def test_checkout_allows_owner_role():
    result, _cp, db, cc = _call_checkout({"role": "owner"})
    assert result["url"] == "https://checkout"
    assert db.fetchone.call_args[0][1][0] == 100
    cc.assert_called_once()


def test_checkout_rejects_unknown_membership():
    err, _cp, db, cc = _call_checkout(None)
    assert isinstance(err, HTTPException)
    assert err.status_code == 403
    cc.assert_not_called()
