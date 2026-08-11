#!/usr/bin/env python3
"""
GSC Bounty Loader — retrieval-based enrichment for Proof-of-Fix and Deep Reduce.

Provides few-shot examples from bounty_examples for:
  1. Proof-of-Fix patch generation (bounty→PoF): "here's how people fixed CWE-X before"
  2. Deep Reduce enrichment (retrieval, not all-by-language)
  3. Revalidator context

Architecture note: Bounty examples are PUBLIC data (GHSA). No DP needed.
They can be freely used in prompts, shared between tenants, and aggregated.

Usage:
    from gsc_bounty_loader import BountyLoader
    loader = BountyLoader()
    
    # For Proof-of-Fix: top-3 fixes for a given CWE+language
    fixes = loader.get_few_shot_fixes(cwe_id="CWE-79", language="javascript", k=3)
    
    # For Deep Reduce: top-3 relevant examples given code snippet
    examples = loader.get_relevant_examples(code_snippet="...", language="python", k=3)
    
    # For revalidator: match finding against nearest examples
    context = loader.get_finding_context(finding_detail="...", language="python")
"""
import os, re, sqlite3, hashlib
from pathlib import Path
from typing import Optional

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")


class BountyLoader:
    """Retrieval-based bounty example loader with relevance scoring."""

    def __init__(self, db_path: str = DB):
        self.db_path = db_path

    def _connect(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db

    # ── 1. Few-shot fixes for Proof-of-Fix ────────────────────────────────────

    def get_few_shot_fixes(self, cwe_id: str, language: str, k: int = 3) -> list[dict]:
        """
        Get top-K real-world fixes for a given CWE+language.
        Used by Proof-of-Fix: "here's how people fixed CWE-X in language Y before."
        
        Returns list of {vulnerable_code, fixed_code, fix_context, fix_quality, summary}
        """
        db = self._connect()
        try:
            # Prefer fix-quality examples (not workarounds)
            examples = db.execute("""
                SELECT vulnerable_code, fixed_code, fix_context, fix_quality,
                       summary, ghsa_id, cve_id
                FROM bounty_examples
                WHERE cwe_id = ? AND language = ? AND fixed_code != ''
                ORDER BY 
                    CASE fix_quality WHEN 'fix' THEN 0 WHEN 'patch' THEN 1 ELSE 2 END,
                    hunk_relevance DESC,
                    collected_at DESC
                LIMIT ?
            """, (cwe_id, language, k)).fetchall()
        except sqlite3.OperationalError:
            db.close()
            return []
        db.close()

        return [
            {
                "vulnerable_code": e["vulnerable_code"][:800],
                "fixed_code": e["fixed_code"][:800],
                "fix_context": (e["fix_context"] or "")[:400],
                "fix_quality": e["fix_quality"],
                "summary": e["summary"][:150],
                "ghsa_id": e["ghsa_id"],
                "cve_id": e["cve_id"],
            }
            for e in examples
        ]

    def build_pof_prompt(self, cwe_id: str, language: str, current_code: str, k: int = 3) -> str:
        """
        Build a Proof-of-Fix prompt section with few-shot examples.
        Inject this into the PoF generator's user prompt.
        """
        fixes = self.get_few_shot_fixes(cwe_id, language, k)
        if not fixes:
            return ""

        lines = [f"\n## 📚 Few-Shot: How developers fixed {cwe_id} in real {language} projects\n"]
        lines.append("Study these fixes before generating your own. Follow their pattern.\n")

        for i, fix in enumerate(fixes, 1):
            lines.append(f"### Example {i}: {fix['summary']} ({fix['ghsa_id']})")
            lines.append(f"Quality: {fix['fix_quality']}")
            if fix["fix_context"]:
                lines.append(f"Context:\n```{language}\n{fix['fix_context']}\n```")
            lines.append(f"**BEFORE (vulnerable):**\n```{language}\n{fix['vulnerable_code']}\n```")
            lines.append(f"**AFTER (fixed):**\n```{language}\n{fix['fixed_code']}\n```")

        lines.append("\n---")
        lines.append(f"Now fix the following {cwe_id} vulnerability in {language}.")
        lines.append(f"Use the same approach as the examples above.")
        lines.append(f"```{language}\n{current_code}\n```")

        return "\n".join(lines)

    # ── 2. Retrieval-based enrichment for Deep Reduce ─────────────────────────

    def get_relevant_examples(self, code_snippet: str, language: str, k: int = 3) -> list[dict]:
        """
        Retrieve top-K bounty examples relevant to a code snippet.
        Uses keyword overlap scoring instead of all-by-language injection.
        """
        db = self._connect()
        try:
            candidates = db.execute("""
                SELECT id, vulnerable_code, fixed_code, fix_context, cwe_id,
                       summary, severity, hunk_relevance
                FROM bounty_examples
                WHERE language = ? AND vulnerable_code != ''
                ORDER BY 
                    CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END,
                    hunk_relevance DESC,
                    collected_at DESC
                LIMIT 50
            """, (language,)).fetchall()
        except sqlite3.OperationalError:
            db.close()
            return []
        db.close()

        if not candidates:
            return []

        # Score by keyword overlap with the code snippet
        snippet_lower = code_snippet.lower()
        snippet_tokens = set(re.findall(r'\b\w{4,}\b', snippet_lower))

        scored = []
        for c in candidates:
            score = 0
            # CWE keyword match
            cwe_pat = (c["cwe_id"] or "").lower()
            if cwe_pat in snippet_lower:
                score += 5

            # Token overlap with vulnerable code
            vuln_lower = (c["vulnerable_code"] or "").lower()
            vuln_tokens = set(re.findall(r'\b\w{4,}\b', vuln_lower))
            overlap = len(snippet_tokens & vuln_tokens)
            if overlap >= 3:
                score += min(overlap, 10)

            # Relevance bonus
            score += (c["hunk_relevance"] or 0) * 3

            scored.append((score, c))

        scored.sort(key=lambda x: -x[0])

        return [
            {
                "vulnerable_code": c["vulnerable_code"][:600],
                "fixed_code": c["fixed_code"][:600],
                "fix_context": (c["fix_context"] or "")[:300],
                "cwe_id": c["cwe_id"],
                "summary": c["summary"][:120],
                "severity": c["severity"],
                "relevance_score": s,
            }
            for s, c in scored[:k] if s > 0
        ]

    def build_enrichment_prompt(self, code_snippet: str, language: str, k: int = 3) -> str:
        """
        Build a retrieval-based enrichment section for Deep Reduce prompts.
        Only injects top-K most relevant examples — not all by language.
        """
        examples = self.get_relevant_examples(code_snippet, language, k)
        if not examples:
            return ""

        lines = [f"\n## 📚 Reference: Real vulnerability patterns (retrieval-matched)"]
        lines.append("The following are REAL vulnerabilities found in production. Compare the code above against these patterns.\n")

        for i, ex in enumerate(examples, 1):
            lines.append(f"### Match {i}: {ex['cwe_id']} — {ex['summary']} (score: {ex['relevance_score']})")
            lines.append(f"**Vulnerable pattern:**\n```{language}\n{ex['vulnerable_code']}\n```")
            if ex['fix_context']:
                lines.append(f"**Context:**\n```{language}\n{ex['fix_context']}\n```")

        return "\n".join(lines)

    # ── 3. Finding context for revalidator ────────────────────────────────────

    def get_finding_context(self, finding_detail: str, language: str, k: int = 2) -> list[dict]:
        """
        For revalidator: match a finding against nearest bounty examples.
        Returns top-K matches with vulnerability/fix pairs.
        """
        db = self._connect()
        try:
            all_examples = db.execute("""
                SELECT vulnerable_code, fixed_code, cwe_id, summary, severity,
                       fix_quality, ghsa_id
                FROM bounty_examples
                WHERE language = ? AND vulnerable_code != ''
                ORDER BY collected_at DESC
                LIMIT 100
            """, (language,)).fetchall()
        except sqlite3.OperationalError:
            db.close()
            return []
        db.close()

        detail_lower = finding_detail.lower()
        detail_tokens = set(re.findall(r'\b\w{4,}\b', detail_lower))

        scored = []
        for e in all_examples:
            score = 0
            # Direct CWE match
            if e["cwe_id"] and e["cwe_id"].lower() in detail_lower:
                score += 10
            # Severity match
            if e["severity"] in ("CRITICAL", "HIGH"):
                score += 2
            # Keyword overlap with summary
            summary_lower = (e["summary"] or "").lower()
            summary_tokens = set(re.findall(r'\b\w{4,}\b', summary_lower))
            overlap = len(detail_tokens & summary_tokens)
            score += min(overlap, 5)
            # Fix quality bonus
            if e["fix_quality"] == "fix":
                score += 1

            scored.append((score, e))

        scored.sort(key=lambda x: -x[0])
        return [
            {
                "cwe_id": e["cwe_id"],
                "summary": e["summary"][:120],
                "severity": e["severity"],
                "fix_quality": e["fix_quality"],
                "vulnerable_code": e["vulnerable_code"][:300],
                "fixed_code": e["fixed_code"][:300],
                "ghsa_id": e["ghsa_id"],
            }
            for score, e in scored[:k] if score > 0
        ]

    # ── 4. Dashboard ──────────────────────────────────────────────────────────

    def dashboard(self) -> dict:
        """Coverage stats: which CWE+lang are approaching auto-generation readiness."""
        db = self._connect()
        try:
            rows = db.execute("""
                SELECT cwe_id, language,
                       COUNT(*) as total,
                       SUM(CASE WHEN fix_quality='fix' THEN 1 ELSE 0 END) as fixes,
                       SUM(CASE WHEN fix_quality='workaround' THEN 1 ELSE 0 END) as workarounds
                FROM bounty_examples
                WHERE cwe_id != ''
                GROUP BY cwe_id, language
                ORDER BY total DESC
            """).fetchall()

            neg_counts = {}
            for r in rows:
                n = db.execute(
                    "SELECT COUNT(*) FROM negative_examples WHERE cwe_id=? AND language=?",
                    (r["cwe_id"], r["language"])
                ).fetchone()[0]
                neg_counts[(r["cwe_id"], r["language"])] = n

            total = db.execute("SELECT COUNT(*) FROM bounty_examples").fetchone()[0]
            total_neg = db.execute("SELECT COUNT(*) FROM negative_examples").fetchone()[0]
        except sqlite3.OperationalError:
            db.close()
            return {"error": "tables not initialized"}
        db.close()

        combos = []
        ready_count = 0
        for r in rows:
            neg = neg_counts.get((r["cwe_id"], r["language"]), 0)
            ready = r["total"] >= 5 and (r["fixes"] or 0) >= 3 and neg >= 1
            if ready:
                ready_count += 1
            combos.append({
                "cwe_id": r["cwe_id"], "language": r["language"],
                "total": r["total"], "fixes": r["fixes"] or 0,
                "workarounds": r["workarounds"] or 0,
                "negatives": neg, "ready": ready,
            })

        return {
            "total_examples": total,
            "total_negatives": total_neg,
            "unique_cwe": len(rows),
            "ready_combos": ready_count,
            "combos": combos,
        }


# ── CLI test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json
    loader = BountyLoader()

    if len(sys.argv) < 2:
        ds = loader.dashboard()
        print(json.dumps({k: v for k, v in ds.items() if k != "combos"}, indent=2))
        for c in ds.get("combos", []):
            r = "✅" if c["ready"] else "  "
            print(f"  {r} {c['cwe_id']:<10} {c['language']:<12} ex={c['total']} f={c['fixes']} w={c['workarounds']} neg={c['negatives']}")
        sys.exit(0)

    if sys.argv[1] == "pof":
        fixes = loader.get_few_shot_fixes("CWE-88", "python")
        print(f"PoF fixes: {len(fixes)}")
        for f in fixes:
            print(f"  {f['ghsa_id']}: {f['summary'][:80]} (q={f['fix_quality']})")

    elif sys.argv[1] == "reduce":
        examples = loader.get_relevant_examples("git.check_unsafe_options(options, unsafe_options)", "python")
        print(f"Reduce matches: {len(examples)}")
        for e in examples:
            print(f"  {e['cwe_id']}: {e['summary'][:80]} (score={e['relevance_score']})")
