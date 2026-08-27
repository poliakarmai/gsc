"""
GSC Collector Items — structured vulnerability data from web scraping.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class VulnerabilityItem:
    """Single vulnerability finding from scraped source."""
    source: str                    # "github", "hackerone", "cve"
    url: str                       # source URL
    title: str                     # finding description
    severity: str = "MEDIUM"       # CRITICAL/HIGH/MEDIUM/LOW
    category: str = ""             # "hardcoded-secret", "jwt", "sql-injection", etc.
    code_snippet: str = ""         # the vulnerable code
    file_path: str = ""            # relative file path (if available)
    line: int = 0                  # line number
    language: str = "python"       # programming language
    pattern_type: str = "regex"    # "regex" | "grep"
    pattern: str = ""              # regex pattern to detect this
    fix_suggestion: str = ""       # how to fix
    references: list[str] = field(default_factory=list)
    matched_detector: str = ""     # which GSC detector matches (GS001-GS015)
    noise_tier: str = "normal"     # precise|normal|noisy
    collected_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    def to_gsc_finding(self) -> dict:
        """Convert to GSC Finding format."""
        return {
            "rule_id": self.matched_detector or "SCRAPED",
            "severity": self.severity,
            "category": self.severity,
            "title": self.title,
            "file_path": self.file_path or self.url,
            "line": self.line,
            "line_number": self.line,
            "detail": self.code_snippet[:500] if self.code_snippet else self.title,
            "fix_suggestion": self.fix_suggestion,
            "references": self.references,
            "noise_tier": self.noise_tier,
            "source": self.source,
            "url": self.url,
            "pattern": self.pattern,
        }

    def to_gsc_pattern(self) -> dict:
        """Convert to GSC seed pattern format."""
        return {
            "title": f"Scraped: {self.title[:80]}",
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "language": self.language,
            "source": self.source,
            "source_url": self.url,
            "references": self.references,
            "active": True,
            "noise_tier": self.noise_tier,
        }
