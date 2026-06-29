"""
GSC Vulnerability Spider — collects security patterns from public sources.

Sources:
  - GitHub code search (hardcoded secrets, JWT, SQL injection, etc.)
  - CVE/NVD database (vulnerability descriptions → patterns)
  - HackerOne hacktivity (disclosed reports with code)

Each finding is fed into the GSC pipeline for pattern creation and self-learning.
"""
import scrapy
import re
import json
import hashlib
from urllib.parse import quote, urljoin
from gsc_collector.items import VulnerabilityItem


# ── Search queries matching GSC detectors ─────────────────────────────────

GITHUB_QUERIES = {
    "GS001-hardcoded-secret": [
        ('"SECRET_KEY" "=" NOT "os.getenv" NOT "environ" language:python', "CRITICAL"),
        ('"API_KEY" "=" NOT "getenv" NOT "environ" language:python', "CRITICAL"),
        ('"password" "=" NOT "getpass" language:python stars:<10', "HIGH"),
        ('"token" "=" "ghp_" language:python', "CRITICAL"),
    ],
    "GS004-dangerous-subprocess": [
        ('"os.system" "f\"" language:python', "HIGH"),
        ('"subprocess" "shell=True" language:python', "HIGH"),
        ('"eval(" "request" language:python stars:<20', "CRITICAL"),
    ],
    "GS005-sql-injection": [
        ('"f\"SELECT" "WHERE" language:python stars:<30', "CRITICAL"),
        ('"f\"INSERT" "VALUES" language:python stars:<30', "CRITICAL"),
        ('".execute" "f\"" "sql" language:python', "HIGH"),
    ],
    "GS011-jwt": [
        ('"jwt.decode" "verify=False" language:python', "CRITICAL"),
        ('"SECRET_KEY" "my_" language:python stars:<10', "HIGH"),
    ],
    "GS012-mass-assignment": [
        ('"**request.POST" "create" language:python stars:<20', "HIGH"),
        ('"**request.data" "save" language:python stars:<20', "HIGH"),
    ],
    "GS014-credentials": [
        ('"postgres://" ":" "@" language:python stars:<15', "HIGH"),
        ('"mongodb://" ":" "@" language:python stars:<15', "HIGH"),
    ],
}


class GscVulnSpider(scrapy.Spider):
    """Collects vulnerability patterns from GitHub code search."""

    name = "gsc_vuln"
    allowed_domains = ["github.com"]
    custom_settings = {
        "USER_AGENT": "GSC-Collector/1.0 (+https://github.com/poliakarmai/gsc)",
        "DOWNLOAD_DELAY": 2,        # Be polite to GitHub
        "CONCURRENT_REQUESTS": 2,   # Rate limiting
        "ROBOTSTXT_OBEY": True,
    }

    def start_requests(self):
        """Generate search requests for all query categories."""
        for category, queries in GITHUB_QUERIES.items():
            for query, severity in queries:
                url = f"https://github.com/search?q={quote(query)}&type=code"
                yield scrapy.Request(
                    url,
                    callback=self.parse_search,
                    meta={"category": category, "severity": severity, "query": query},
                    dont_filter=True,
                )

    def parse_search(self, response):
        """Parse GitHub search results page."""
        category = response.meta["category"]
        severity = response.meta["severity"]
        query = response.meta["query"]

        # GitHub code search results are in div elements
        code_results = response.css("div.code-list-item")

        for result in code_results[:10]:  # Top 10 per query
            try:
                # Extract repo and file info
                repo_link = result.css("a[data-testid='breadcrumb-link']::attr(href)").get()
                file_path = result.css("div.f4 a::text").get() or ""
                repo_name = result.css("a[data-testid='breadcrumb-link']::text").get() or ""

                if repo_link:
                    file_url = urljoin("https://github.com", repo_link)
                    if file_path:
                        file_url = f"{file_url.rstrip('/')}/blob/master/{file_path}"

                    item = VulnerabilityItem(
                        source="github",
                        url=file_url or response.url,
                        title=f"GitHub code search: {category}",
                        severity=severity,
                        category=category,
                        file_path=file_path,
                        language="python",
                        matched_detector=category.split("-")[0].upper() if "-" in category else "",
                        pattern=query,
                        references=[response.url],
                        noise_tier="normal",
                    )
                    yield item

            except Exception:
                continue

        # Pagination
        next_page = response.css("a.next_page::attr(href)").get()
        if next_page:
            yield response.follow(
                next_page,
                callback=self.parse_search,
                meta=response.meta,
            )


class CveNvdSpider(scrapy.Spider):
    """Collects CVE descriptions for pattern extraction."""

    name = "cve_nvd"
    allowed_domains = ["nvd.nist.gov", "services.nvd.nist.gov"]

    def start_requests(self):
        # NVD API: recent CVEs with known exploits
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=20"
        yield scrapy.Request(url, callback=self.parse_cves)

    def parse_cves(self, response):
        """Parse NVD CVE API response."""
        try:
            data = json.loads(response.text)
        except json.JSONDecodeError:
            return

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            # Extract severity
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
            base_score = cvss_v31.get("cvssData", {}).get("baseScore", 0)
            severity = "CRITICAL" if base_score >= 9 else "HIGH" if base_score >= 7 else "MEDIUM"

            # Extract vulnerable patterns from description
            patterns = self._extract_patterns(desc_en, cve_id)

            for pat in patterns:
                yield VulnerabilityItem(
                    source="cve",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    title=f"{cve_id}: {desc_en[:120]}",
                    severity=severity,
                    category=pat.get("category", ""),
                    code_snippet=pat.get("snippet", desc_en[:200]),
                    pattern=pat.get("pattern", ""),
                    pattern_type=pat.get("pattern_type", "grep"),
                    language=pat.get("language", "python"),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    noise_tier="normal",
                )

    def _extract_patterns(self, description: str, cve_id: str) -> list[dict]:
        """Extract grep'able patterns from CVE description."""
        patterns = []

        # Common vulnerability phrases → grep patterns
        pattern_map = {
            r"(?:hard.?coded|hardcoded)\s+(?:password|secret|key|token|credential)":
                {"category": "hardcoded-secret", "language": "python"},
            r"SQL\s+(?:injection|inject)":
                {"category": "sql-injection", "language": "python", "pattern": "f\"SELECT"},
            r"(?:cross.?site\s+scripting|XSS)":
                {"category": "xss", "language": "javascript"},
            r"(?:command\s+injection|OS\s+command)":
                {"category": "command-injection", "language": "python", "pattern": "os.system"},
            r"(?:path\s+traversal|directory\s+traversal)":
                {"category": "path-traversal", "language": "python"},
            r"(?:deserialization|pickle|unserialize)":
                {"category": "deserialization", "language": "python", "pattern": "pickle.loads"},
            r"(?:authentication\s+bypass|auth\s+bypass)":
                {"category": "auth-bypass", "language": "python"},
            r"(?:SSRF|server.?side\s+request\s+forgery)":
                {"category": "ssrf", "language": "python", "pattern": "requests.get"},
            r"(?:buffer\s+overflow|buffer\s+overrun)":
                {"category": "buffer-overflow", "language": "c"},
            r"(?:use.?after.?free|UAF)":
                {"category": "use-after-free", "language": "c"},
        }

        for regex, meta in pattern_map.items():
            if re.search(regex, description, re.I):
                patterns.append({
                    "snippet": description[:200],
                    "category": meta.get("category", "unknown"),
                    "pattern": meta.get("pattern", regex),
                    "pattern_type": "grep",
                    "language": meta.get("language", "python"),
                })

        return patterns


class HackerOneSpider(scrapy.Spider):
    """Collects disclosed vulnerability reports from HackerOne hacktivity."""

    name = "hackerone"
    allowed_domains = ["hackerone.com"]

    def start_requests(self):
        url = "https://hackerone.com/hacktivity?order_field=disclosed_at&filter=type%3Apublic"
        yield scrapy.Request(url, callback=self.parse_hacktivity)

    def parse_hacktivity(self, response):
        """Parse HackerOne hacktivity page."""
        reports = response.css("div[data-testid='hacktivity-item']")

        for report in reports[:10]:
            try:
                title = report.css("h3 a::text").get() or ""
                severity_text = report.css("span.severity span::text").get() or "Medium"
                url = report.css("h3 a::attr(href)").get() or ""
                bounty = report.css("span.bounty-amount::text").get() or ""

                # Map severity
                sev = severity_text.strip().upper()
                if "CRITICAL" in sev:
                    severity = "CRITICAL"
                elif "HIGH" in sev:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                yield VulnerabilityItem(
                    source="hackerone",
                    url=urljoin("https://hackerone.com", url) if url else response.url,
                    title=title[:120],
                    severity=severity,
                    category="disclosed-report",
                    noise_tier="normal",
                    references=[urljoin("https://hackerone.com", url)] if url else [],
                )
            except Exception:
                continue
