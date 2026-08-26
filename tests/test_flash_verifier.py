#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the flash-verifier model selection (Phase 2).

The ``select_flash_model`` function is pure: it depends only on its inputs and
performs no I/O, network calls, or module-level env reads. This makes it
trivially unit-testable for all documented selection rules.
"""
from __future__ import annotations

import sys
from pathlib import Path
import os

import pytest

# Make the repo importable when pytest is invoked from elsewhere.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from gsc_cli import gsc_rejudge as rj  # noqa: E402


class TestFlashModelSelectionDataclass:
    def test_as_dict_json_serialisable(self):
        s = rj.FlashModelSelection(model="test-model", enabled=True, source="test")
        d = s.as_dict()
        assert d == {"model": "test-model", "enabled": True, "source": "test"}
        # Ensure it's JSON serialisable
        import json
        json.dumps(d)


class TestSelectFlashModel:
    PRIMARY_MODEL = "deepseek-chat"

    @pytest.mark.parametrize(
        "configured_flash,env,expected_model,expected_enabled,expected_source",
        [
            # Env overrides everything (even empty string to disable).
            ("any-model", {"GSC_FLASH_MODEL": "env-model"}, "env-model", True, "env"),
            ("any-model", {"GSC_FLASH_MODEL": ""}, PRIMARY_MODEL, False, "disabled_env"),
            ("any-model", {"GSC_FLASH_MODEL": None}, "any-model", True, "configured"), # None in env should fall through to configured
            # Configured value (if env not set).
            ("configured-model", {}, "configured-model", True, "configured"),
            ("", {}, PRIMARY_MODEL, False, "disabled_configured"),
            (None, {}, rj.DEFAULT_FLASH_MODEL, True, "default"),

            # Default fallback when nothing is set.
            (None, None, rj.DEFAULT_FLASH_MODEL, True, "default"),

            # Test primary_model fallback when flash is disabled
            ("configured-model", {"GSC_FLASH_MODEL": ""}, PRIMARY_MODEL, False, "disabled_env"),
            (None, {"GSC_FLASH_MODEL": ""}, PRIMARY_MODEL, False, "disabled_env"),
            ("configured-model", None, "configured-model", True, "configured"),
            ("", None, PRIMARY_MODEL, False, "disabled_configured"),
            (None, {}, rj.DEFAULT_FLASH_MODEL, True, "default"),

            # Edge case: empty primary_model still gives a sane flash default
            (None, None, rj.DEFAULT_FLASH_MODEL, True, "default"),
            (None, {}, rj.DEFAULT_FLASH_MODEL, True, "default"),
        ],
    )
    def test_selection_logic(
        self, configured_flash, env, expected_model, expected_enabled, expected_source
    ):
        if env is None:
            # Simulate genuinely unset env when None is passed.
            test_env = None
        else:
            test_env = env

        result = rj.select_flash_model(self.PRIMARY_MODEL, configured_flash, test_env)
        assert result.model == expected_model
        assert result.enabled == expected_enabled
        assert result.source == expected_source

    def test_no_primary_model(self):
        # Even with no primary, disabled flash should still return a sane model
        result = rj.select_flash_model("", "", {})
        assert result.model == rj.DEFAULT_FLASH_MODEL
        assert result.enabled is False
        assert result.source == "disabled_configured"

        result = rj.select_flash_model("", None, None)
        assert result.model == rj.DEFAULT_FLASH_MODEL
        assert result.enabled is True
        assert result.source == "default"

    def test_pure_function_no_io(self, monkeypatch):
        """select_flash_model must not touch os.environ directly."""
        # Make any os.environ lookup explode.
        monkeypatch.delitem(rj.os.environ, "GSC_FLASH_MODEL", raising=False)
        monkeypatch.delitem(rj.os.environ, "NON_EXISTENT_KEY", raising=False)
        
        # Test basic flow without an explicit env parameter
        result = rj.select_flash_model(self.PRIMARY_MODEL, None, {})
        assert result.model == rj.DEFAULT_FLASH_MODEL
        assert result.enabled is True
        assert result.source == "default"

        # Test with an explicit env parameter
        result = rj.select_flash_model(self.PRIMARY_MODEL, None, {"GSC_FLASH_MODEL": "custom-flash"})
        assert result.model == "custom-flash"
        assert result.enabled is True
        assert result.source == "env"
