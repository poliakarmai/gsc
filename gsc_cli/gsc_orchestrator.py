#!/usr/bin/env python3
"""Master Orchestrator (v0.39). Unified pipeline: scan→enrich→chains→sbom→report."""
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class PipelineResult:
    target: str; profile: str
    findings: List[Dict] = field(default_factory=list)
    chains: List[Dict] = field(default_factory=list)
    sbom: Optional[Dict] = None
    summaries: Dict = field(default_factory=dict)

    def to_dict(self): return asdict(self)


class GSCOrchestrator:
    def __init__(self, scanner, config: Dict = None):
        self.scanner = scanner; self.config = config or {}

    def run(self, target: str, profile: str, with_sbom=True, with_chains=True) -> PipelineResult:
        result = PipelineResult(target=target, profile=profile)
        result.findings = self._scan(target, profile)
        result.findings = self._enrich(result.findings)
        if with_chains: result.chains = self._compose(result.findings)
        if with_sbom: result.sbom = self._sbom(target)
        result.summaries = self._summary(result)
        return result

    def _scan(self, target, profile):
        try: return self.scanner.scan(target, profile)
        except: return []

    def _enrich(self, findings):
        try:
            from gsc_compliance import enrich_finding
            findings = [enrich_finding(f) for f in findings]
        except ImportError: pass
        try:
            from gsc_epss import enrich_sca_findings
            findings = enrich_sca_findings(findings, db=getattr(self.scanner, 'db', None))
        except ImportError: pass
        return findings

    def _compose(self, findings):
        try:
            from gsc_chain_composer import compose
            return compose(findings)
        except: return []

    def _sbom(self, target):
        try:
            from gsc_sbom import generate_sbom
            from gsc_sca import parse_repo_manifests
            pkgs = parse_repo_manifests(target)
            return generate_sbom(pkgs) if pkgs else None
        except: return None

    def _summary(self, result):
        by_sev = {}
        for f in result.findings:
            s = f.get("severity", "UNKNOWN"); by_sev[s] = by_sev.get(s, 0) + 1
        return {"total": len(result.findings), "by_severity": by_sev,
                "chains": len(result.chains),
                "sbom_components": len(result.sbom.get("components", [])) if result.sbom else 0,
                "critical": by_sev.get("CRITICAL", 0)}
