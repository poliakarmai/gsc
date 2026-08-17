#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GS030 — SCA detector. Thin wrapper over gsc_sca for external scan pipeline."""

from pathlib import Path
from gsc_core.gsc_sca import parse_repo_manifests, query_osv, sca_findings


class GS030Detector:
    rule_id = "GS030"
    name = "Software Composition Analysis (dependencies CVE)"
    requires_llm = False

    def detect_repo(self, repo_root, db=None):
        packages = parse_repo_manifests(repo_root)
        if not packages:
            return []
        osv_results = query_osv(packages, db=db)
        return sca_findings(packages, osv_results)
