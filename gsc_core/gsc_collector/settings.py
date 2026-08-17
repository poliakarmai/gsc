from pathlib import Path
"""
GSC Collector — Scrapy settings.
"""
BOT_NAME = "gsc_collector"
SPIDER_MODULES = ["gsc_core.gsc_collector.spiders"]
NEWSPIDER_MODULE = "gsc_core.gsc_collector.spiders"

# Polite crawling
USER_AGENT = "GSC-Collector/1.0 (+https://github.com/poliakarmai/gsc)"
ROBOTSTXT_OBEY = True
DOWNLOAD_DELAY = 2
CONCURRENT_REQUESTS = 2
CONCURRENT_REQUESTS_PER_DOMAIN = 1

# Pipelines
ITEM_PIPELINES = {
    "gsc_core.gsc_collector.pipelines.GscDatabasePipeline": 300,
    "gsc_core.gsc_collector.pipelines.ObsidianExportPipeline": 400,
    "gsc_core.gsc_collector.pipelines.JsonExportPipeline": 500,
}

# Cache (don't re-download unchanged pages)
HTTPCACHE_ENABLED = True
HTTPCACHE_EXPIRATION_SECS = 86400  # 24 hours
HTTPCACHE_DIR = "/tmp/gsc_collector_cache"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = str(Path.home() / ".hermes" / "logs" / "gsc_collector.log")

# Timeouts
DOWNLOAD_TIMEOUT = 30
RETRY_TIMES = 2

# Export
FEED_EXPORT_ENCODING = "utf-8"
