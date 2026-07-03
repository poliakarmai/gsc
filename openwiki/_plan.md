# OpenWiki Plan — GSC (Git Security Checker)

## Pages to Create

### 1. quickstart.md
- Project identity, what GSC does
- Key facts: 15 plugin detectors, 350+ patterns, 3 echelons, Deepsec-inspired pipeline
- Links to all other pages
- Source evidence: /README.md, /AGENTS.md, /pyproject.toml, /CHANGELOG.md, /docs/*.md

### 2. architecture/
- Pipeline overview (scan → revalidate → export)
- 3 echelons + E4 LLM deep analysis
- Plugin detector system (AuditContext, Finding, DetectorEntry)
- Resume scanner (FileStateManager)
- Structured revalidator
- Source evidence: /gsc.py, /gsc_detectors/__init__.py, /gsc_detectors/registry.py, 
  /gsc_resume.py, /gsc_revalidate.py, /scripts/e4_llm.py, /scripts/framework_aware.py

### 3. detectors/
- Every detector: rule_id, tier, severity, category, what it catches
- GS001–GS016 + LLM verify
- How to add a detector
- Pattern storage (seed JSON + DB auto-creation)
- Noise tiers, inline suppression
- Source evidence: /gsc_detectors/*.py, /patterns/*.json, /patterns/docs/PATTERNS.md

### 4. operations/
- Installation (ripgrep + Python)
- CLI commands (gsc scan, init, dashboard, patterns, triage, etc.)
- CI/CD integration (GitHub Action, pre-commit hook, Helm chart)
- LLM configuration (OpenRouter, DeepSeek, cost guardrails)
- DB encryption, baseline management
- Source evidence: /action.yml, /helm/*, /pre-commit, /scripts/gsc_doctor.py,
  /scripts/gsc_baseline.py, /scripts/db_encrypt.py, /scripts/gsc_issue.py,
  /scripts/gsc_pr_comment.py, /scripts/gsc_config.py

### 5. testing/
- Corpus tests (8 tests, pytest-compatible)
- How to add tests
- Key test: scan_file() helper creates temp git repo, runs scan, checks JSON output
- Source evidence: /tests/test_corpus.py, /corpus/*.py

### 6. workflows/
- Full audit workflow: init → scan → triage → revalidate → fix
- Self-learning loop: findings → patterns → future scans
- LLM triage workflow (E4)
- Collector workflow (Scrapy + lightweight)
- GitHub Dorks scanner
- Source evidence: /gsc.py cmd_*, /gsc_github_dorks.py, /gsc_collect_light.py,
  /gsc_collector/gsc_collector/spiders/gsc_vuln_spider.py

## Deleted page consideration
- Data model page → merge into architecture (SQLite schema is already in code)
- Integration page → merge into operations (CI/CD, Helm, VSCode are narrow enough)

## Remaining questions
- How is the Obsidian vault path configured? → config.yaml, docs/CONFIG.md
- How does auto-learning from TP findings work? → scripts/gsc_export_knowledge.py, metrics.py
- Exact SQLite schema? → visible in pipelines.py and gsc.py
