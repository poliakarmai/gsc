#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты подписи GSC — гарантия, что подпись всегда присутствует в PR/commit."""
import pytest

from gsc_cli.gsc_signature import (
    pr_signature,
    commit_signature,
    co_author_trailer,
    badge_markdown,
    comment_signature,
    label_name,
    sign_commit_message,
    DEFAULT_REPO_URL,
)


class TestPrSignature:
    def test_contains_repo_link(self):
        assert DEFAULT_REPO_URL in pr_signature()

    def test_contains_powered_by(self):
        assert "Powered by" in pr_signature()

    def test_empty_when_disabled(self, monkeypatch):
        monkeypatch.setenv("GSC_SIGNATURE_ENABLED", "0")
        assert pr_signature() == ""
        assert commit_signature() == ""
        assert badge_markdown() == ""
        assert label_name() == ""

    def test_verified_and_poc_shows_full_proof(self):
        sig = pr_signature(verified=True, poc_success=True)
        assert "Proof-of-Fix" in sig
        assert "provably effective" in sig

    def test_verified_only(self):
        sig = pr_signature(verified=True)
        assert "Proof-of-Fix" in sig
        assert "provably effective" not in sig

    def test_short_mode_minimal(self):
        sig = pr_signature(mode="short")
        assert "Powered by" in sig
        assert "Proof-of-Fix" not in sig  # краткий режим без деталей

    def test_rule_id_included_when_provided(self):
        assert "GS005" in pr_signature(rule_id="GS005")

    def test_rule_id_absent_by_default(self):
        assert "Detected by rule" not in pr_signature()


class TestCommitSignature:
    def test_commit_trailer_format(self):
        trailer = commit_signature()
        assert trailer.startswith("GSC-Signed-By:")
        assert DEFAULT_REPO_URL in trailer

    def test_co_author_empty_by_default(self):
        # до создания GitHub App co-author пуст (no-op)
        assert co_author_trailer() == ""

    def test_co_author_from_env(self, monkeypatch):
        monkeypatch.setenv(
            "GSC_SIGNATURE_COAUTHOR",
            "gsc-bot[bot] <gsc-bot@users.noreply.github.com>",
        )
        assert co_author_trailer().startswith("Co-authored-by: gsc-bot")

    def test_sign_commit_message_adds_trailer(self):
        msg = sign_commit_message("fix: sql injection")
        assert msg.startswith("fix: sql injection")
        assert "GSC-Signed-By:" in msg

    def test_sign_commit_message_exact(self):
        msg = sign_commit_message("fix: x")
        assert msg == f"fix: x\n\nGSC-Signed-By: {DEFAULT_REPO_URL}"

    def test_sign_commit_message_disabled(self, monkeypatch):
        monkeypatch.setenv("GSC_SIGNATURE_ENABLED", "0")
        assert sign_commit_message("fix: x") == "fix: x"


class TestBadgeAndLabel:
    def test_badge_has_shields(self):
        b = badge_markdown()
        assert "shields.io" in b
        assert "GSC" in b

    def test_label_name(self):
        assert label_name() == "gsc-verified"


class TestCommentSignature:
    def test_comment_signature_has_scanned_by(self):
        sig = comment_signature()
        assert "Scanned by" in sig
        assert DEFAULT_REPO_URL in sig

    def test_comment_signature_disabled(self, monkeypatch):
        monkeypatch.setenv("GSC_SIGNATURE_ENABLED", "0")
        assert comment_signature() == ""


class TestProofOfFixIntegration:
    def test_evidence_to_markdown_has_signature(self):
        from gsc_cli.gsc_proofoffix import evidence_to_markdown, FixEvidence
        ev = FixEvidence(
            finding_key="GS005-1",
            rule_id="GS005",
            file_path="app.py",
            line_number=12,
            level="verified",
            verified=True,
            exploited_before=True,
            exploited_after=False,
        )
        md = evidence_to_markdown(ev)
        assert "Powered by" in md
        assert DEFAULT_REPO_URL in md
        assert "Proof-of-Fix" in md

    def test_evidence_to_markdown_failed_has_signature_but_not_verified(self):
        from gsc_cli.gsc_proofoffix import evidence_to_markdown, FixEvidence
        ev = FixEvidence(finding_key="GS020-2", level="failed")
        md = evidence_to_markdown(ev)
        # подпись есть всегда (GSC сгенерировал отчёт), но verified-маркер отсутствует
        assert "Powered by" in md
        assert "patch was verified by GSC sandbox" not in md


class TestNucleiExportSignature:
    def test_template_has_gsc_reference(self):
        from gsc_cli.gsc_nuclei_export import NucleiTemplate
        t = NucleiTemplate(
            id="gsc-test",
            name="Test Finding",
            severity="medium",
            description="d",
            requests=[],
        )
        y = t.to_yaml()
        assert "gsc-auto" in y            # author
        assert DEFAULT_REPO_URL in y      # reference на репозиторий


class TestSelfHealingIntegration:
    def test_selfhealing_imports_and_exposes_pr(self):
        # smoke: selfhealing импортируется и имеет точку создания PR
        import gsc_cli.gsc_selfhealing as sh
        assert callable(sh._create_autofix_pr)
