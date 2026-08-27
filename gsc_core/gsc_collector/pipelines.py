"""
GSC Collector Pipeline — feeds scraped findings into GSC ecosystem.

Three outputs:
  1. GSC SQLite DB — patterns + findings tables (for self-learning)
  2. Obsidian vault — markdown notes for human review
  3. JSON export — for downstream processing
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from gsc_core.gsc_collector.items import VulnerabilityItem


class GscDatabasePipeline:
    """Save findings and patterns to GSC SQLite database."""

    def __init__(self):
        self.db_path = Path.home() / ".hermes" / "state" / "gsc_audit.db"
        self.items_processed = 0
        self.patterns_created = 0

    def open_spider(self, spider):
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")

    def close_spider(self, spider):
        spider.logger.info(
            f"GSC Pipeline: {self.items_processed} findings, "
            f"{self.patterns_created} new patterns"
        )
        self.conn.close()

    def process_item(self, item: VulnerabilityItem, spider):
        """Save item as finding + pattern to GSC DB."""
        finding = item.to_gsc_finding()
        pattern = item.to_gsc_pattern()

        # 1. Insert or update pattern
        pattern_hash = self._hash_pattern(pattern["pattern"])
        existing = self.conn.execute(
            "SELECT id FROM patterns WHERE pattern_hash=? LIMIT 1",
            (pattern_hash,)
        ).fetchone()

        if not existing and pattern["pattern"]:
            try:
                self.conn.execute(
                    """INSERT INTO patterns
                       (title, pattern, pattern_type, severity, language,
                        source, source_url, references, active, noise_tier, pattern_hash, project)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '*')""",
                    (pattern["title"], pattern["pattern"], pattern["pattern_type"],
                     pattern["severity"], pattern["language"], pattern["source"],
                     pattern["source_url"], json.dumps(pattern["references"]),
                     pattern["active"], pattern["noise_tier"], pattern_hash)
                )
                self.patterns_created += 1
                pattern_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            except sqlite3.IntegrityError:
                pattern_id = None
        else:
            pattern_id = existing[0] if existing else None

        # 2. Insert finding
        try:
            from gsc_db import compute_finding_key
            self.conn.execute(
                """INSERT INTO findings
                   (project, rule_id, category, severity, title, file_path,
                    line_number, detail, fix_suggestion, references, noise_tier,
                    source, url, pattern_id, finding_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("gsc-collector", finding["rule_id"], finding["category"],
                 finding["severity"], finding["title"], finding["file_path"],
                 finding["line"], finding["detail"], finding["fix_suggestion"],
                 json.dumps(finding["references"]), finding["noise_tier"],
                 finding["source"], finding["url"], pattern_id,
                 compute_finding_key(finding["rule_id"], finding["file_path"], finding["detail"]))
            )
            self.items_processed += 1
        except Exception as e:
            spider.logger.error(f"Failed to save finding: {e}")

        self.conn.commit()
        return item

    def _hash_pattern(self, pattern: str) -> str:
        import hashlib
        return hashlib.md5(pattern.encode()).hexdigest()[:16]


class ObsidianExportPipeline:
    """Export findings to Obsidian vault for human review."""

    def __init__(self):
        self.vault_path = Path.home() / "obsidian-vault" / "hermes" / "gsc-collector"
        self.items: list[VulnerabilityItem] = []

    def open_spider(self, spider):
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.items = []

    def close_spider(self, spider):
        if not self.items:
            return

        # Group by source
        by_source = {}
        for item in self.items:
            by_source.setdefault(item.source, []).append(item)

        # Write per-source markdown files
        timestamp = datetime.now().strftime("%Y-%m-%d")
        for source, items in by_source.items():
            filename = f"{source}-{timestamp}.md"
            filepath = self.vault_path / filename

            with open(filepath, "w") as f:
                f.write("---\n")
                f.write(f"title: \"GSC Collector — {source} ({timestamp})\"\n")
                f.write(f"source: {source}\n")
                f.write(f"collected: {datetime.now().isoformat()}\n")
                f.write(f"count: {len(items)}\n")
                f.write("type: gsc-collector\n")
                f.write("---\n\n")
                f.write(f"# GSC Collector — {source}\n\n")
                f.write(f"**{len(items)}** findings collected on {timestamp}.\n\n")
                f.write("## Findings\n\n")

                for i, item in enumerate(items):
                    f.write(f"### {i+1}. {item.severity}: {item.title[:80]}\n")
                    f.write(f"- **Source:** [{item.source}]({item.url})\n")
                    f.write(f"- **Category:** {item.category}\n")
                    f.write(f"- **Detector:** {item.matched_detector}\n")
                    f.write(f"- **Language:** {item.language}\n")
                    f.write(f"- **Pattern:** `{item.pattern[:100]}`\n")
                    if item.code_snippet:
                        f.write(f"\n```{item.language}\n{item.code_snippet[:500]}\n```\n")
                    f.write("\n---\n\n")

            spider.logger.info(f"Obsidian: {len(items)} findings → {filepath}")

        # Update index
        self._update_index()

    def process_item(self, item: VulnerabilityItem, spider):
        self.items.append(item)
        return item

    def _update_index(self):
        """Update the collector index."""
        index_path = self.vault_path / "00-Index.md"
        files = sorted(self.vault_path.glob("*.md"))

        with open(index_path, "w") as f:
            f.write("---\n")
            f.write("title: \"GSC Collector — Index\"\n")
            f.write("type: index\n")
            f.write(f"updated: {datetime.now().isoformat()}\n")
            f.write(f"total_files: {len(files)}\n")
            f.write("---\n\n")
            f.write("# GSC Collector\n\n")
            f.write("Automated vulnerability pattern collection for GSC self-learning.\n\n")
            f.write("## Collected batches\n\n")
            for fp in sorted(files, reverse=True):
                if fp.name == "00-Index.md":
                    continue
                name = fp.stem
                size = fp.stat().st_size
                f.write(f"- [[{name}]] ({size} bytes)\n")


class JsonExportPipeline:
    """Export findings as JSON for downstream processing."""

    def __init__(self):
        self.output_dir = Path.home() / ".hermes" / "state" / "gsc_collector"
        self.items: list[dict] = []

    def open_spider(self, spider):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.items = []

    def close_spider(self, spider):
        if not self.items:
            return

        timestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        filepath = self.output_dir / f"findings-{timestamp}.json"

        with open(filepath, "w") as f:
            json.dump(self.items, f, indent=2, ensure_ascii=False)

        spider.logger.info(f"JSON: {len(self.items)} findings → {filepath}")

    def process_item(self, item: VulnerabilityItem, spider):
        self.items.append(item.to_dict())
        return item
