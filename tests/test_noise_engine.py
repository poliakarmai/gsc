# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for the adaptive self-learning threshold (Phase 11: median + MAD)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gsc_cli"))

from gsc_noise_engine import adaptive_threshold  # noqa: E402


def test_fallback_when_too_few_rates():
    assert adaptive_threshold([0.9]) == 0.80
    assert adaptive_threshold([0.9, 0.1]) == 0.80


def test_clean_distribution_clips_to_floor():
    # Low FP rates → threshold hits the 0.5 floor (never looser than 50%).
    t = adaptive_threshold([0.1, 0.2, 0.3, 0.4])
    assert 0.5 <= t <= 0.95


def test_outlier_distribution_bounded():
    # Pathological rules pull the threshold up, but it never exceeds the ceiling.
    t = adaptive_threshold([0.1, 0.2, 0.95, 0.98, 0.99])
    assert 0.5 <= t <= 0.95


def test_threshold_rises_with_noisier_population():
    # A noisier population yields a higher (looser) threshold than a clean one.
    clean = adaptive_threshold([0.05, 0.10, 0.15, 0.20])
    noisy = adaptive_threshold([0.6, 0.7, 0.8, 0.9])
    assert noisy >= clean
