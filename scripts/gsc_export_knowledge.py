#!/usr/bin/env python3
"""
GSC Knowledge Export — упаковывает находки в тренировочный датасет для AI-агентов.

Форматы:
  --format jsonl    : OpenAI fine-tuning формат (system/user/assistant)
  --format jsonl-simple : строки JSONL с полями code/finding/label
  --format markdown : human-readable отчёт
"""

import os, sys, json, sqlite3, argparse
from pathlib import Path
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

def export_jsonl(output: str, limit: int = 5000):
    """Export as OpenAI fine-tuning format — system/user/assistant triples."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("""
        SELECT f.*, p.effectiveness, p.language, p.fix as pattern_fix
        FROM findings f
        LEFT JOIN patterns p ON f.pattern_title = p.title
        WHERE f.status IN ('fixed', 'confirmed', 'false_positive', 'open')
        ORDER BY CASE f.category 
            WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 
            WHEN 'MEDIUM' THEN 2 ELSE 3 END
        LIMIT ?
    """, (limit,)).fetchall()
    
    exported = 0
    with open(output, 'w') as out:
        for row in rows:
            row = dict(row)
            label = "TRUE_POSITIVE" if row['status'] in ('fixed', 'confirmed') else \
                   "FALSE_POSITIVE" if row['status'] == 'false_positive' else "UNVERIFIED"
            
            code_context = ""
            fp = row.get('file_path', '')
            ln = row.get('line_number', 0)
            if fp and ln and Path(fp).exists():
                try:
                    lines = Path(fp).read_text().split("\n")
                    start = max(0, ln - 3)
                    end = min(len(lines), ln + 3)
                    code_context = "\n".join(lines[start:end])
                except:
                    pass

            entry = {
                "messages": [
                    {"role": "system", "content": "You are a code security auditor. Given a finding and code context, determine if this is a REAL vulnerability (TRUE_POSITIVE) or a FALSE_POSITIVE. Consider: docstrings, type annotations, test files, guarded usage, security tools that intentionally use dangerous patterns."},
                    {"role": "user", "content": f"Finding: [{row['category']}] {row['title']}\nDetail: {row.get('detail','')}\nFile: {fp}:{ln}\n\nCode:\n```\n{code_context[:2000]}\n```\n\nReal vulnerability or false positive?"},
                    {"role": "assistant", "content": label}
                ]
            }
            out.write(json.dumps(entry, ensure_ascii=False) + "\n")
            exported += 1
    
    conn.close()
    return exported


def export_jsonl_simple(output: str, limit: int = 10000):
    """Export as simple JSONL rows — compact, good for bulk training."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("""
        SELECT category, title, detail, file_path, line_number, status, pattern_title
        FROM findings
        WHERE status IN ('fixed', 'confirmed', 'false_positive')
        ORDER BY CASE category 
            WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END
        LIMIT ?
    """, (limit,)).fetchall()
    
    exported = 0
    with open(output, 'w') as out:
        for row in rows:
            row = dict(row)
            entry = {
                "finding": f"[{row['category']}] {row['title']}",
                "detail": row.get('detail', ''),
                "file": f"{row.get('file_path','')}:{row.get('line_number',0)}",
                "label": "tp" if row['status'] in ('fixed', 'confirmed') else "fp",
                "pattern": row.get('pattern_title', '')
            }
            out.write(json.dumps(entry, ensure_ascii=False) + "\n")
            exported += 1
    
    conn.close()
    return exported


def export_markdown(output: str, limit: int = 200):
    """Export as human-readable Markdown report."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    
    # Summary
    total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()['c']
    tp = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status IN ('fixed','confirmed')").fetchone()['c']
    fp = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status='false_positive'").fetchone()['c']
    active = conn.execute("SELECT COUNT(*) as c FROM patterns WHERE active=1").fetchone()['c']
    
    # Top patterns by TP
    top_tp = conn.execute("""
        SELECT p.title, p.category, p.effectiveness, 
               SUM(CASE WHEN f.status IN ('fixed','confirmed') THEN 1 ELSE 0 END) as tp
        FROM patterns p
        LEFT JOIN findings f ON f.pattern_title = p.title
        WHERE p.active = 1
        GROUP BY p.id
        ORDER BY tp DESC LIMIT 10
    """).fetchall()
    
    # Top False Positive patterns
    top_fp = conn.execute("""
        SELECT p.title, p.category, 
               SUM(CASE WHEN f.status='false_positive' THEN 1 ELSE 0 END) as fp
        FROM patterns p
        LEFT JOIN findings f ON f.pattern_title = p.title
        GROUP BY p.id
        ORDER BY fp DESC LIMIT 10
    """).fetchall()
    
    # Recent CRITICAL findings
    recent = conn.execute("""
        SELECT * FROM findings 
        WHERE category='CRITICAL' AND status IN ('fixed','confirmed','false_positive')
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    
    conn.close()
    
    prec = tp / max(1, tp + fp) * 100
    
    with open(output, 'w') as out:
        out.write(f"# GSC Knowledge Report\n\n")
        out.write(f"**Экспортирован:** {datetime.now().isoformat()}\n\n")
        out.write(f"## Сводка\n\n")
        out.write(f"| Метрика | Значение |\n")
        out.write(f"|---------|----------|\n")
        out.write(f"| Всего находок | {total:,} |\n")
        out.write(f"| True Positive | {tp:,} |\n")
        out.write(f"| False Positive | {fp:,} |\n")
        out.write(f"| Precision | {prec:.1f}% |\n")
        out.write(f"| Активных паттернов | {active} |\n\n")
        
        out.write(f"## Лучшие паттерны (по TP)\n\n")
        out.write(f"| Паттерн | TP | Эффективность |\n")
        out.write(f"|---------|:---:|:------------:|\n")
        for row in top_tp:
            out.write(f"| [{row['category']}] {row['title'][:60]} | {row['tp']} | {(row['effectiveness'] or 0):.0%} |\n")
        
        out.write(f"\n## Самые шумные паттерны (по FP)\n\n")
        out.write(f"| Паттерн | FP |\n")
        out.write(f"|---------|:---:|\n")
        for row in top_fp:
            out.write(f"| [{row['category']}] {row['title'][:60]} | {row['fp']} |\n")
        
        out.write(f"\n## Последние CRITICAL находки\n\n")
        for row in recent:
            row = dict(row)
            emoji = "✅" if row['status'] in ('fixed','confirmed') else "❌"
            out.write(f"- {emoji} [{row['category']}] **{row['title']}** — `{row.get('file_path','?')}:{row.get('line_number',0)}`\n")
            if row.get('detail'):
                out.write(f"  - {row['detail'][:200]}\n")
        
        out.write(f"\n---\n*GSC v0.5 — самообучающийся аудитор кода*\n")
    
    return total


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="GSC Knowledge Export")
    p.add_argument("--format", choices=["jsonl", "jsonl-simple", "markdown"], default="jsonl-simple")
    p.add_argument("--output", help="Output file (default: auto)")
    p.add_argument("--limit", type=int, default=5000, help="Max findings to export")
    args = p.parse_args()
    
    if not args.output:
        ext = {"jsonl": "jsonl", "jsonl-simple": "jsonl", "markdown": "md"}
        args.output = f"/tmp/gsc_knowledge_{datetime.now().strftime('%Y%m%d')}.{ext[args.format]}"
    
    if args.format == "jsonl":
        n = export_jsonl(args.output, args.limit)
        print(f"✅ OpenAI fine-tuning: {n} примеров → {args.output}")
    elif args.format == "jsonl-simple":
        n = export_jsonl_simple(args.output, args.limit)
        print(f"✅ Simple JSONL: {n} строк → {args.output}")
    elif args.format == "markdown":
        n = export_markdown(args.output, args.limit)
        print(f"✅ Markdown: {n} находок → {args.output}")
