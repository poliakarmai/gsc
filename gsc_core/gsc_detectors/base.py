"""Unified detector contract (refactor #1). All detectors implement BaseDetector."""
from __future__ import annotations
import hashlib, re
from typing import Dict, List, Tuple

def make_finding(rule_id: str, title: str, severity: str, confidence: float,
                 file: str, line: int, snippet: str,
                 metadata: Dict | None = None, invariant: bool = False) -> Dict:
    if not rule_id or not str(rule_id).strip():
        import warnings
        warnings.warn(f"make_finding: empty rule_id — skipped. title={title!r} file={file!r}")
        return None  # caller must handle: if f is None → skip
    key = hashlib.sha256(f"{rule_id}{file}{snippet}".encode()).hexdigest()[:12]
    # Contract: downstream (gsc_external.py) reads file_path / line_number / detail
    # and category. Emit BOTH the canonical keys and the legacy aliases so
    # nothing depending on the old names breaks.
    return {"finding_key": key, "rule_id": rule_id, "title": title,
            "severity": severity, "category": severity, "confidence": confidence,
            "file_path": file, "file": file,
            "line_number": line, "line": line,
            "detail": snippet[:200], "snippet": snippet[:200],
            "invariant": invariant,
            "metadata": metadata or {}}


class BaseDetector:
    rule_id: str = "GS000"
    requires_llm: bool = False
    languages: Tuple[str, ...] = ()

    def detect(self, file_path: str, content: str, language: str = "auto") -> List[Dict]:
        raise NotImplementedError


class RegexDetector(BaseDetector):
    def __init__(self, rule_id: str, name: str, patterns: List[Tuple[str, str]],
                 severity: str, confidence: float, languages: Tuple[str, ...] = (),
                 not_patterns: List[str] | None = None):
        self.rule_id = rule_id; self.name = name
        self.severity = severity; self.confidence = confidence
        self.languages = languages
        self._compiled = [(re.compile(p), desc) for p, desc in patterns]
        self._not_compiled = [re.compile(p) for p in (not_patterns or [])]

    def detect(self, file_path, content, language="auto") -> List[Dict]:
        findings = []
        for pattern, title in self._compiled:
            for m in pattern.finditer(content):
                line = _line_at(content, m.start())
                if self._negated(line):
                    continue
                line_no = content[:m.start()].count("\n") + 1
                findings.append(make_finding(
                    rule_id=self.rule_id, title=title, severity=self.severity,
                    confidence=self.confidence, file=file_path,
                    line=line_no, snippet=m.group(0)[:200],
                    invariant=True))  # regex detector → structural invariant, not a guess
        return findings

    def _negated(self, line: str) -> bool:
        """True если строка с матчем попадает под negation-guard (pattern-not)."""
        return any(np.search(line) for np in self._not_compiled)


def _line_at(content: str, pos: int) -> str:
    """Вернуть строку исходника, содержащую позицию pos."""
    start = content.rfind("\n", 0, pos) + 1
    end = content.find("\n", pos)
    if end == -1:
        end = len(content)
    return content[start:end]
