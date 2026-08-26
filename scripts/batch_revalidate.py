#!/usr/bin/env python3
"""
GSC Batch Revalidator v3 — agent-assisted mode.
Agent fetches findings, classifies them with LLM, then updates DB.
"""

import os, sys, json, sqlite3
from datetime import datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gsc_cli.gsc_revalidate import Revalidator
from gsc_core.gsc_db import GSCDatabase
from gsc_cli.gsc_llm_providers import get_manager

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
BATCH_SIZE = 500


def fetch_findings(limit=BATCH_SIZE, rule_id_filter=None, days_old_filter=None):
    """Output findings as JSON for agent to classify — prioritized by uncertainty."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    
    query_parts = [
        "SELECT f.id, f.category, f.title, f.project, f.file_path, ",
        "       f.line_number, f.detail, f.echelon, f.confidence_score, f.pattern_id, f.rule_id, f.revalidation_checked_at",
        "FROM findings f",
        "WHERE f.revalidation_verdict IS NULL",
        "  AND f.detail IS NOT NULL AND f.detail != ''",
        "  AND f.project IS NOT NULL",
        "  AND f.project != '.'",
        "  AND f.project NOT LIKE '/home/%'",
        "  AND f.project NOT LIKE '/opt/%'",
        "  AND f.project NOT LIKE '/tmp/tmp%'",
        "  AND f.project NOT LIKE '%benchmark%'",
        "  AND f.project NOT LIKE '%pof_corpus%'",
        "  AND COALESCE(f.file_path, '') NOT LIKE '/home/%'",
        "  AND COALESCE(f.file_path, '') NOT LIKE '/opt/%'",
        "  AND COALESCE(f.file_path, '') NOT LIKE '/tmp/tmp%'",
        "  AND COALESCE(f.file_path, '') NOT LIKE '%benchmark%'",
        "  AND COALESCE(f.file_path, '') NOT LIKE '%pof_corpus%'"
    ]
    
    params = []
    if rule_id_filter:
        query_parts.append(" AND f.rule_id = ?")
        params.append(rule_id_filter)
        
    if days_old_filter:
        cutoff_date = (datetime.now().astimezone() - timedelta(days=days_old_filter)).isoformat()
        query_parts.append(" AND f.revalidation_checked_at < ?")
        params.append(cutoff_date)

    query_parts.extend([
        "ORDER BY",
        "    CASE WHEN f.confidence_score BETWEEN 40 AND 70 THEN 0 ELSE 1 END,",
        "    f.confidence_score DESC NULLS LAST,",
        "    f.id DESC",
        "LIMIT ?",
    ])
    params.append(limit)
    
    rows = db.execute(" ".join(query_parts), params).fetchall()
    db.close()
    
    findings = []
    for r in rows:
        fdata = {
            "id": r["id"],
            "category": r["category"],
            "title": r["title"] or "",
            "project": r["project"] or "",
            "file_path": f"{r['file_path']}:{r['line_number']}" if r['file_path'] and r['line_number'] else (r["file_path"] or "?"),
            "detail": (r["detail"] or "")[:200],
            "rule_id": r["rule_id"],
            "confidence_score": r["confidence_score"],
            "revalidation_checked_at": r["revalidation_checked_at"]
        }
        findings.append(fdata)
    
    print(json.dumps({"count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
    return len(findings)


def update_db(results_json):
    """Update DB with agent classifications. Input: {"0": "TP", "1": "FP", ...}"""
    
    # Initialize Revalidator and check LLM availability
    db_path_str = os.environ.get("GSC_DB_PATH", DB)
    project_path_str = os.environ.get("GSC_PROJECT_PATH", ".")
    revalidator = Revalidator(db_path_str, Path(project_path_str))
    
    use_llm = bool(get_manager().providers) # True if any LLM providers are configured
    
    if not use_llm:
        print("LLM provider not available. Performing dry-run revalidation.")

    # Parse findings from input
    try:
        findings_data = json.loads(results_json)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON input received: {results_json[:100]}", file=sys.stderr)
        return 0

    # Prepare findings for revalidator
    findings_to_revalidate = []
    for idx_str, verdict_or_context in findings_data.items():
        finding_id = None # Initialize
        try:
            finding_id = int(idx_str)
            if isinstance(verdict_or_context, str) and verdict_or_context.upper() in ("TP", "FP", "FIX"):
                # Agent already provided a verdict (this should ideally not happen with the new fetch)
                # If it does, we'll just log it and skip revalidation for this finding
                print(f"Finding {finding_id} already has a verdict: {verdict_or_context}. Skipping revalidation.", file=sys.stderr)
                continue
            elif isinstance(verdict_or_context, dict):
                # Agent provided context, use it
                finding_data = verdict_or_context
                finding_data["id"] = finding_id # Ensure ID is present
                findings_to_revalidate.append(finding_data)
            else:
                print(f"Warning: Unexpected data format for finding ID {finding_id}: {verdict_or_context}. Skipping.", file=sys.stderr)
        except ValueError:
            print(f"Error: Invalid finding ID format: {idx_str}. Skipping.", file=sys.stderr)
        except Exception as e:
            if finding_id is not None:
                print(f"Error processing finding ID {finding_id}: {e}. Skipping.", file=sys.stderr)
            else:
                print(f"Error processing finding with ID string '{idx_str}': {e}. Skipping.", file=sys.stderr)

    if not findings_to_revalidate:
        print("No findings to revalidate.")
        return 0

    # Perform revalidation
    revalidation_results = revalidator.revalidate_findings_batch(findings_to_revalidate, use_llm=use_llm)

    # Process results and update DB
    stats = {"TP": 0, "FP": 0, "FIX": 0, "uncertain": 0, "updated": 0}
    now = datetime.now().isoformat()

    for result in revalidation_results:
        finding_id = result.get("id")
        if not finding_id:
            print(f"Warning: Finding missing ID in revalidation results: {result}", file=sys.stderr)
            continue

        verdict = result.get("revalidation_verdict", "uncertain").upper()
        stats[verdict.lower()] = stats.get(verdict.lower(), 0) + 1
        stats["updated"] += 1

        # Update DB using direct SQL to ensure persistence
        db_conn = sqlite3.connect(db_path_str)
        try:
            db_conn.execute(
                """
                UPDATE findings
                SET revalidation_verdict = ?,
                    revalidation_reasoning = ?,
                    revalidation_checked_at = ?,
                    revalidation_git_fixed = ?
                WHERE id = ?
                """,
                (
                    result.get("revalidation_verdict"),
                    result.get("revalidation_reasoning"),
                    now,
                    result.get("revalidation_git_fixed"),
                    finding_id,
                )
            )
            db_conn.commit()
        except Exception as e:
            print(f"Error updating DB for finding ID {finding_id}: {e}", file=sys.stderr)
        finally:
            db_conn.close()

    # Count uncertain verdicts if LLM was off or failed
    if not use_llm:
        stats["uncertain"] = len(findings_to_revalidate) - stats["updated"]

    # Auto-deactivation logic (from original script)
    # Rules with <30% TP rate across >=10 verdicts are auto-deactivated.
    db_conn_for_deactivation = sqlite3.connect(db_path_str)
    cursor_deactivation = db_conn_for_deactivation.cursor()
    
    now_deactivation = datetime.now().isoformat()
    
    try:
        # Get IDs of findings we just processed for the IN clause
        processed_ids = [str(r.get("id")) for r in revalidation_results if r.get("id") is not None]
        if not processed_ids:
            # No findings processed, skip deactivation check
            pass
        else:
            placeholders = ",".join("?" * len(processed_ids))
            query = f"""
                SELECT COALESCE(NULLIF(pattern_id, ""), COALESCE(NULLIF(category, ""), rule_id)) as rule_key,
                       COUNT(*) as total,
                       SUM(CASE WHEN revalidation_verdict = 'TP' THEN 1 ELSE 0 END) as tp
                FROM findings
                WHERE revalidation_verdict IS NOT NULL AND id IN ({placeholders})
                GROUP BY rule_key
                HAVING total >= 10
            """
            cursor_deactivation.execute(query, processed_ids)
            rules = cursor_deactivation.fetchall()
            
            for r in rules:
                rule_key = r[0]
                total = r[1]
                tp = r[2]
                
                if total > 0:
                    tp_rate = tp / total
                    if tp_rate < 0.30:
                        reason = f"global_tp_rate={tp_rate:.2f}@{total}verdicts"
                        # Check if already deactivated
                        existing = cursor_deactivation.execute(
                            "SELECT 1 FROM federated_deactivated WHERE rule_id = ?", (rule_key,)
                        ).fetchone()
                        if not existing:
                            cursor_deactivation.execute(
                                "INSERT INTO federated_deactivated (rule_id, reason, deactivated_at) VALUES (?, ?, ?)",
                                (rule_key, reason, now_deactivation)
                            )
                            stats[f"DEACTIVATED_{rule_key}"] = 1
                            print(f"  🛑 AUTO-DEACTIVATED: {rule_key} (TP={tp_rate:.2f} at {total} verdicts)")
        
        db_conn_for_deactivation.commit()
    except Exception as e:
        print(f"Error during auto-deactivation check: {e}", file=sys.stderr)
    finally:
        db_conn_for_deactivation.close()

    print(json.dumps(stats, indent=2))
    return stats["updated"]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: batch_revalidate.py --fetch [N] [--rule-id <ID>] [--days-old <N>] | --update '<json>'")
        sys.exit(1)
    
    if sys.argv[1] == "--fetch":
        limit = BATCH_SIZE
        rule_id_filter = None
        days_old_filter = None

        i = 2
        while i < len(sys.argv):
            if sys.argv[i].isdigit():
                limit = int(sys.argv[i])
                i += 1
            elif sys.argv[i] == "--rule-id" and i + 1 < len(sys.argv):
                rule_id_filter = sys.argv[i+1]
                i += 2
            elif sys.argv[i] == "--days-old" and i + 1 < len(sys.argv) and sys.argv[i+1].isdigit():
                days_old_filter = int(sys.argv[i+1])
                i += 2
            else:
                print(f"Unknown argument for --fetch: {sys.argv[i]}", file=sys.stderr)
                sys.exit(1)
        fetch_findings(limit, rule_id_filter=rule_id_filter, days_old_filter=days_old_filter)
    elif sys.argv[1] == "--update":
        update_db(sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read())
    else:
        print("Unknown command")
        sys.exit(1)