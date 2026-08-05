#!/usr/bin/env python3
"""
GSC Exploit Chain Composer v0.18.

Composes isolated findings into multi-step attack chains.
Chain is reported ONLY if composed_severity > max(individual severities).
Requires LLM. Auto-disabled in fork-safe (--no-llm) mode.

Candidate selection uses rule categories and heuristics before LLM
to conserve budget. Chains are persisted in SQLite via gsc_db.py.
"""

import hashlib, itertools, json, re, sys, os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_NAMES = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

RULE_CATEGORIES = {
    "GS001": "injection", "GS004": "injection", "GS005": "injection",
    "GS007": "authz", "GS012": "info-leak",
    "GS014": "info-leak",
    "GS019": "auth", "GS011": "auth",
    "GS022": "ssrf", "GS021": "ssrf",
    "GS020": "injection",
    "GS024": "llm-injection",
    "GS025-permissive_cors": "exposure",
    "GS025-debug_mode": "exposure",
    "GS025-wildcard_bind": "exposure",
    "GS025-hardcoded_secret": "secret",
    "GS025-eval_usage": "injection",
    "GS010": "exposure", "GS016": "exposure",
}
DEFAULT_CATEGORY = "other"

DEFAULTS = {
    "confirm_threshold": 0.70,
    "max_findings_per_chain": 3,
    "max_candidates": 12,
    "context_window": 15,
}

REDACT_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "API key"),
    (r'AKIA[A-Z0-9]{16}', "AWS key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub token"),
    (r'-----BEGIN.*PRIVATE KEY-----', "Private key"),
    (r'password\s*[=:]\s*["\'][^\s"\']{8,}["\']', "Hardcoded credential"),
]


def _get_api_key() -> str:
    for p in [Path(os.path.expanduser("~/.hermes/.env")),
              Path(os.path.expanduser("~/.hermes/env"))]:
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def _call_llm(system: str, user: str, max_tokens: int = 900) -> Optional[str]:
    import urllib.request as _req
    key = _get_api_key()
    if not key:
        return None
    body = json.dumps({
        "model": "deepseek-chat",
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    try:
        resp = json.loads(_req.urlopen(_req.Request(
            "https://api.deepseek.com/v1/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        ), timeout=30).read())
        return resp["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[Chain] LLM error: {e}", file=sys.stderr)
        return None


def _redact_check(text: str) -> bool:
    for pattern, label in REDACT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            print(f"[Chain] REDACT: {label}", file=sys.stderr)
            return False
    return True


@dataclass
class AttackChain:
    chain_key: str
    finding_keys: list[str]
    composed_severity: str
    confidence: float
    narrative: str
    steps: list[dict] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ChainComposer:
    """Composes individual findings into multi-step attack chains."""

    def __init__(self, budget: int, config: Optional[dict] = None):
        cfg = {**DEFAULTS, **(config or {})}
        self.budget = budget
        self.confirm_threshold = float(cfg.get("confirm_threshold", 0.70))
        self.max_per_chain = int(cfg.get("max_findings_per_chain", 3))
        self.max_candidates = int(cfg.get("max_candidates", 12))
        self.context_window = int(cfg.get("context_window", 15))

    # ── Public API ───────────────────────────────────────────

    def compose(self, findings: list[dict],
                source_map: dict[str, str]) -> list[AttackChain]:
        candidates = self._select_candidates(findings)
        chains: list[AttackChain] = []
        for candidate in candidates:
            if self.budget <= 0:
                break
            self.budget -= 1
            raw = _call_llm(
                "You are a senior security analyst. Determine whether these "
                "findings can be chained into a single multi-step exploit. "
                "Use ONLY the provided code. Do not invent absent code.",
                self._build_prompt(candidate, source_map),
                max_tokens=900,
            )
            if not raw:
                continue
            chain = self._parse_and_validate(raw, candidate)
            if chain:
                chains.append(chain)
        return self._dedupe_chains(chains)

    # ── Candidate selection (pre-LLM heuristics) ─────────────

    def _select_candidates(self, findings) -> list[list[dict]]:
        active = [f for f in findings if f.get("confidence", 0) >= 0.35]
        by_file: dict[str, list] = {}
        for f in active:
            fp = f.get("file", f.get("file_path", ""))
            by_file.setdefault(fp, []).append(f)

        candidates = []
        for fs in by_file.values():
            if len(fs) < 2:
                continue
            for n in range(2, self.max_per_chain + 1):
                for combo in itertools.combinations(fs, n):
                    if self._is_plausible(list(combo)):
                        candidates.append(list(combo))

        candidates.sort(key=self._priority, reverse=True)
        return candidates[:self.max_candidates]

    def _is_plausible(self, combo: list[dict]) -> bool:
        rule_ids = {f.get("rule_id", f.get("pattern_title", ""))
                    for f in combo}
        if len(rule_ids) < 2:
            return False
        cats = {self._category(f.get("rule_id", f.get("pattern_title", "")))
                for f in combo}
        return len(cats) >= 2

    def _priority(self, combo: list[dict]) -> float:
        cats = {self._category(f.get("rule_id", f.get("pattern_title", "")))
                for f in combo}
        score = len(cats) * 2.0
        if "info-leak" in cats and ({"injection", "authz", "auth"} & cats):
            score += 3.0
        if "secret" in cats:
            score += 2.0
        sevs = [SEVERITY_ORDER.get(
            f.get("severity", f.get("category", "LOW")), 1
        ) for f in combo]
        score += (max(sevs) - min(sevs)) * 1.5
        score += sum(f.get("confidence", 0) for f in combo) / len(combo)
        return score

    def _category(self, rule_id: str) -> str:
        for prefix in sorted(RULE_CATEGORIES, key=len, reverse=True):
            if rule_id.startswith(prefix):
                return RULE_CATEGORIES[prefix]
        return DEFAULT_CATEGORY

    # ── LLM prompt ───────────────────────────────────────────

    def _build_prompt(self, candidate, source_map) -> str:
        finding_lines = "\n".join(
            f"- finding_key={f.get('finding_key','?')} "
            f"rule={f.get('rule_id', f.get('pattern_title','?'))} "
            f"severity={f.get('severity', f.get('category','?'))} "
            f"file={f.get('file', f.get('file_path',''))}:{f.get('line', f.get('line_number','?'))} "
            f"— {f.get('title', '')}"
            for f in candidate
        )
        ctx = self._combined_context(candidate, source_map)
        return (
            f"Determine whether these findings can be chained into "
            f"a single multi-step exploit.\n\n"
            f"Findings:\n{finding_lines}\n\n"
            f"Code context:\n{ctx}\n\n"
            f"Rules:\n"
            f"- A chain is valid ONLY if combined impact exceeds max individual severity\n"
            f"- Rely strictly on provided code; don't invent code that is absent\n"
            f"- Consider data flow, trust boundaries, authentication dependencies\n"
            f"Output JSON:\n"
            f'{{"exploitable": true|false, "composed_severity": "LOW|MEDIUM|HIGH|CRITICAL",\n'
            f' "confidence": 0.0-1.0, "narrative": "attack description",\n'
            f' "steps": [{{"step": 1, "finding_key": "...", "action": "..."}}],\n'
            f' "preconditions": ["..."],\n'
            f'}}'
        )

    def _combined_context(self, candidate, source_map) -> str:
        parts = []
        for f in candidate:
            fp = f.get("file", f.get("file_path", ""))
            src = source_map.get(fp, "// [source not available]")
            lines = src.splitlines()
            ln = f.get("line", f.get("line_number", 1)) - 1
            start = max(0, ln - self.context_window)
            end = min(len(lines), ln + self.context_window + 1)
            parts.append(
                f"### {fp}:{ln + 1}\n" +
                "\n".join(lines[start:end])
            )
        return "\n\n".join(parts)

    # ── LLM response validation ──────────────────────────────

    def _parse_and_validate(self, raw: str,
                            candidate: list[dict]) -> Optional[AttackChain]:
        m = re.search(r"\{[^{}]*\"exploitable\"[^{}]*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None

        if not data.get("exploitable"):
            return None

        sev = str(data.get("composed_severity", "")).upper()
        if sev not in SEVERITY_ORDER:
            return None

        try:
            conf = float(data.get("confidence", 0))
        except (TypeError, ValueError):
            return None
        if not (0.0 <= conf <= 1.0):
            return None
        if conf < self.confirm_threshold:
            return None

        # Rule: chain MUST upgrade severity
        max_ind = max(
            SEVERITY_ORDER.get(
                f.get("severity", f.get("category", "LOW")), 1
            ) for f in candidate
        )
        if SEVERITY_ORDER[sev] <= max_ind:
            return None

        narrative = str(data.get("narrative", ""))[:500]
        if not _redact_check(narrative):
            return None

        fkeys = [f.get("finding_key", "") for f in candidate]
        steps = data.get("steps", [])
        valid_keys = set(fkeys)
        steps = [s for s in steps
                 if isinstance(s, dict) and s.get("finding_key") in valid_keys]

        return AttackChain(
            chain_key=self._chain_key(fkeys),
            finding_keys=fkeys,
            composed_severity=sev,
            confidence=round(conf, 2),
            narrative=narrative,
            steps=steps,
            preconditions=[str(p) for p in data.get("preconditions", [])][:5],
        )

    @staticmethod
    def _chain_key(finding_keys: list[str]) -> str:
        return hashlib.sha256("|".join(sorted(finding_keys)).encode()).hexdigest()[:12]

    def _dedupe_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        chains.sort(key=lambda c: (len(c.finding_keys), c.confidence), reverse=True)
        kept: list[AttackChain] = []
        for chain in chains:
            keys = set(chain.finding_keys)
            if any(keys < set(k.finding_keys) for k in kept):
                continue
            kept.append(chain)
        return kept
