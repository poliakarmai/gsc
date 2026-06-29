#!/usr/bin/env python3
"""
GSC Collector Runner — запуск сбора уязвимостей через Scrapy.

Usage:
    python3 gsc_collector.py github      # только GitHub code search
    python3 gsc_collector.py cve         # только CVE/NVD
    python3 gsc_collector.py hackerone   # только HackerOne hacktivity
    python3 gsc_collector.py all         # все источники (медленно)
    python3 gsc_collector.py quick       # быстрый сбор (1 стр/запрос, без пагинации)
"""
import sys
import os
from pathlib import Path

# Ensure we're in the right directory
os.chdir(Path(__file__).parent)

SPIDERS = {
    "github": "gsc_vuln",
    "cve": "cve_nvd",
    "hackerone": "hackerone",
}


def run_spider(spider_name: str, fast: bool = False):
    """Run a single spider."""
    from scrapy.crawler import CrawlerProcess
    from scrapy.utils.project import get_project_settings

    settings = get_project_settings()
    if fast:
        settings.set("CONCURRENT_REQUESTS", 3)
        settings.set("DOWNLOAD_DELAY", 1)
        settings.set("CLOSESPIDER_ITEMCOUNT", 20)  # Limit for quick mode

    process = CrawlerProcess(settings)
    process.crawl(spider_name)
    process.start()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 gsc_collector.py [github|cve|hackerone|all|quick]")
        sys.exit(1)

    mode = sys.argv[1]
    fast = mode == "quick"

    if mode in ("all", "quick"):
        for source, spider in SPIDERS.items():
            print(f"\n{'='*60}")
            print(f"  Running: {source} ({spider})")
            print(f"{'='*60}\n")
            try:
                run_spider(spider, fast=fast)
            except Exception as e:
                print(f"  ❌ {source} failed: {e}")
    elif mode in SPIDERS:
        run_spider(SPIDERS[mode])
    else:
        print(f"Unknown mode: {mode}. Use: github, cve, hackerone, all, quick")
        sys.exit(1)


if __name__ == "__main__":
    main()
