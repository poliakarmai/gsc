#!/usr/bin/env python3
"""GSC Nuclei Template Importer v1.0 — Wave 2. Imports nuclei YAML into DB for DAST."""
from __future__ import annotations
import json, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
try:
    import yaml
except ImportError:
    print("Install: pip install pyyaml"); sys.exit(1)

@dataclass
class NucleiTemplate:
    id: str; name: str; severity: str; description: str
    tags: List[str]; requests: List[Dict]; matchers: List[Dict]

    @classmethod
    def from_yaml(cls, yaml_path: str) -> Optional["NucleiTemplate"]:
        try:
            with open(yaml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"  ⚠ {Path(yaml_path).name}: parse error — {e}")
            return None
        if not isinstance(data, dict):
            return None
        info = data.get("info", {})
        template_id = data.get("id", "")
        if not template_id:
            return None
        requests_block = data.get("http") or data.get("requests") or []
        if not isinstance(requests_block, list):
            requests_block = [requests_block]
        matchers = []
        if requests_block and "matchers" in requests_block[0]:
            matchers = requests_block[0]["matchers"]
        tags = info.get("tags", "")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif not isinstance(tags, list):
            tags = []
        return cls(
            id=template_id, name=info.get("name", template_id),
            severity=info.get("severity", "info").lower(),
            description=info.get("description", ""), tags=tags,
            requests=requests_block, matchers=matchers,
        )

    def to_db_row(self) -> dict:
        return {
            "template_id": self.id, "name": self.name,
            "severity": self.severity, "description": (self.description or "")[:500],
            "tags": json.dumps(self.tags), "requests": json.dumps(self.requests),
            "matchers": json.dumps(self.matchers),
        }


def import_nuclei_directory(directory: str, db_path: str = None) -> dict:
    dir_path = Path(directory)
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    yaml_files = list(dir_path.rglob("*.yaml")) + list(dir_path.rglob("*.yml"))
    stats = {"imported": 0, "skipped": 0, "errors": 0}
    from gsc_db import GSCDatabase
    with (GSCDatabase(db_path) if db_path else GSCDatabase()) as db:
        for yaml_file in yaml_files:
            template = NucleiTemplate.from_yaml(str(yaml_file))
            if not template:
                stats["skipped"] += 1
                continue
            try:
                row = template.to_db_row()
                db.conn.execute("""
                    INSERT INTO nuclei_templates
                        (template_id, name, severity, description, tags, requests, matchers)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(template_id) DO UPDATE SET
                        name = excluded.name, severity = excluded.severity,
                        description = excluded.description, tags = excluded.tags,
                        requests = excluded.requests, matchers = excluded.matchers
                """, (row["template_id"], row["name"], row["severity"],
                      row["description"], row["tags"], row["requests"], row["matchers"]))
                stats["imported"] += 1
            except Exception as e:
                print(f"  ⚠ {yaml_file.name}: DB error — {e}")
                stats["errors"] += 1
        db.conn.commit()
    return stats


def list_templates(severity: str = None, tag: str = None, db_path: str = None) -> List[dict]:
    from gsc_db import GSCDatabase
    with (GSCDatabase(db_path) if db_path else GSCDatabase()) as db:
        sql = "SELECT * FROM nuclei_templates WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity = ?"
            params.append(severity.lower())
        if tag:
            sql += " AND tags LIKE ?"
            params.append(f"%{tag}%")
        sql += " ORDER BY severity, template_id"
        rows = db.conn.execute(sql, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC Nuclei Template Importer")
    sub = p.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import", help="Import nuclei YAML templates")
    imp.add_argument("directory", help="Path to nuclei-templates/")
    lst = sub.add_parser("list", help="List imported templates")
    lst.add_argument("--severity", choices=["info","low","medium","high","critical"])
    lst.add_argument("--tag")
    args = p.parse_args()
    if args.cmd == "import":
        try:
            stats = import_nuclei_directory(args.directory)
            print(f"\n✅ Imported {stats['imported']} templates")
            if stats["skipped"]: print(f"   Skipped: {stats['skipped']}")
            if stats["errors"]: print(f"   Errors: {stats['errors']}")
        except FileNotFoundError as e:
            print(f"❌ {e}"); sys.exit(1)
    elif args.cmd == "list":
        templates = list_templates(args.severity, args.tag)
        if not templates:
            print("No templates imported."); return
        print(f"{'ID':<40} {'Sev':<10} {'Name'}")
        print("-" * 80)
        for t in templates[:50]:
            print(f"{t['template_id']:<40} {t['severity']:<10} {t['name'][:45]}")
        if len(templates) > 50: print(f"\n... and {len(templates) - 50} more")

if __name__ == "__main__":
    main()
