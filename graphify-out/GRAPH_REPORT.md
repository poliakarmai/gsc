# Graph Report - .  (2026-08-02)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 589 nodes · 815 edges · 63 communities (55 shown, 8 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 9 edges (avg confidence: 0.53)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `806be39e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- VulnerabilityItem
- package.json
- FileStateManager
- Revalidator
- analyze_finding
- Path
- AuditContext
- GscCollector
- gsc.py
- fastapi_support.py
- cmd_scan
- GscCollectorSpiderMiddleware
- main
- gs009_supply_chain.py
- .get_source_files
- db_encrypt.py
- test_corpus.py
- batch_and_override.py
- django_cross_org.py
- gs005_sql_injection.py
- Finding
- llm_verify.py
- gsc_github_dorks.py
- framework_filter
- extension.js
- gs008_dead_code.py
- gsc_issue.py
- TicketController
- _cron_collect.py
- gs002_world_readable.py
- gs003_debug_prints.py
- gsc_export_knowledge.py
- post_pr_comment
- analyze_reachability
- check_source_driven
- cmd_triage
- gs001_hardcoded_secret.py
- gs007_idor.py
- gs014_credential_exposure.py
- gs016_linux_priv_esc.py
- gsc_config.py
- gsc_baseline.py
- cmd_patterns
- DetectorEntry
- generate_seed_patterns
- express_files.js
- gsc_collector.py
- export_pdf
- corpus_gs005_python.py
- pre-commit
- gsc

## God Nodes (most connected - your core abstractions)
1. `AuditContext` - 42 edges
2. `Finding` - 40 edges
3. `FileStateManager` - 21 edges
4. `VulnerabilityItem` - 19 edges
5. `Revalidator` - 18 edges
6. `cmd_scan()` - 14 edges
7. `run_audit_echelons()` - 12 edges
8. `main()` - 12 edges
9. `GscCollector` - 12 edges
10. `analyze_finding()` - 11 edges

## Surprising Connections (you probably didn't know these)
- `cmd_scan()` --calls--> `analyze_reachability()`  [INFERRED]
  gsc.py → scripts/gsc_reachability.py
- `cmd_scan()` --calls--> `FileStateManager`  [EXTRACTED]
  gsc.py → gsc_resume.py
- `check_plugin_detectors()` --calls--> `AuditContext`  [EXTRACTED]
  gsc.py → gsc_detectors/__init__.py
- `check_plugin_detectors()` --calls--> `get_detectors()`  [EXTRACTED]
  gsc.py → gsc_detectors/registry.py
- `check_deep()` --calls--> `run_e4_scan()`  [EXTRACTED]
  gsc.py → scripts/e4_llm.py

## Import Cycles
- None detected.

## Communities (63 total, 8 thin omitted)

### Community 0 - "VulnerabilityItem"
Cohesion: 0.05
Nodes (26): GSC Collector Items — structured vulnerability data from web scraping., Single vulnerability finding from scraped source., Convert to GSC Finding format., Convert to GSC seed pattern format., VulnerabilityItem, GscDatabasePipeline, JsonExportPipeline, ObsidianExportPipeline (+18 more)

### Community 1 - "package.json"
Cohesion: 0.06
Nodes (35): Linters, onCommand:gsc.scanCurrent, onCommand:gsc.showFindings, Other, activationEvents, author, categories, properties (+27 more)

### Community 2 - "FileStateManager"
Cohesion: 0.07
Nodes (17): FileStateManager, Path, GSC Resume Scanner — Deepsec-inspired per-file state tracking. Allows scans to…, Mark file as scanned (regex pass done)., Mark file as processed (AI analysis done)., Skip a file (non-code, test, etc.)., Check if file content changed since last scan., Reset file to pending if content changed. Returns True if reset. (+9 more)

### Community 3 - "Revalidator"
Cohesion: 0.09
Nodes (16): Path, GSC Structured Revalidate — Deepsec-inspired revalidation stage. Re-checks…, Read code context around the finding., Fast heuristic checks before LLM call. Returns (verdict_or_None, reason)., Revalidate a single finding. Returns finding dict with revalidation fields., Revalidate multiple findings. Returns updated findings., Quick LLM check when git shows recent changes. Returns verdict., Full structured LLM revalidation. In production, this would call… (+8 more)

### Community 4 - "analyze_finding"
Cohesion: 0.15
Nodes (19): analyze_finding(), analyze_local(), call_openrouter(), check_cache(), collect_related(), get_cache_key(), Generate deterministic cache key., Check if this finding was already analyzed. (+11 more)

### Community 5 - "Path"
Cohesion: 0.16
Nodes (19): check_adversarial(), check_deep(), check_plugin_detectors(), check_security(), _is_in_docstring_or_comment(), _is_suppressed_inline(), load_patterns(), Path (+11 more)

### Community 6 - "AuditContext"
Cohesion: 0.16
Nodes (14): detect(), GS004 — Dangerous subprocess usage (command injection risk). Detects: -…, Find dangerous subprocess/shell usage in source code., detect(), GS011 — JWT/JOSE Vulnerability Detector Echelon: 2 (SECURITY) Category:…, detect(), GS012 — Mass Assignment Vulnerability Detector Echelon: 2 (SECURITY) Category:…, detect() (+6 more)

### Community 7 - "GscCollector"
Cohesion: 0.18
Nodes (8): GscCollector, main(), Collect recent CVEs from NVD. Fetches the most recently published., Extract security patterns from CVE description., Collect vulnerability patterns from GitHub code search API., Save pattern + finding to GSC DB., Export latest collection to Obsidian vault., Lightweight vulnerability pattern collector.

### Community 8 - "gsc.py"
Cohesion: 0.15
Nodes (16): cmd_dashboard(), get_detectors(), Get detectors, optionally filtered by echelon., generate_dashboard_html(), generate_pattern_rows(), generate_project_rows(), get_dashboard_stats(), _init_db() (+8 more)

### Community 9 - "fastapi_support.py"
Cohesion: 0.18
Nodes (10): download_attachment(), get_org_ticket(), get_support_ticket(), Test: FastAPI — support panel without auth, file download, cross-org access.…, No auth check — anyone can access support tickets., Unprotected file download — no ownership check., Has user auth BUT missing org/tenant check., secure_ticket() (+2 more)

### Community 10 - "cmd_scan"
Cohesion: 0.14
Nodes (14): cmd_scan(), Verify multiple findings, prioritizing by severity. Limits to max_per_batch for…, verify_findings(), export_sarif(), export_to_obsidian(), print_compliance(), print_summary(), Print compliance report for PCI DSS, SOC2, or ISO 27001. (+6 more)

### Community 12 - "main"
Cohesion: 0.15
Nodes (13): cmd_db(), cmd_explain(), cmd_fix(), cmd_init(), cmd_revalidate(), cmd_status(), main(), Run SQL query against GSC database. (+5 more)

### Community 13 - "gs009_supply_chain.py"
Cohesion: 0.17
Nodes (9): detect(), _find_bumblebee(), GS009 — Supply Chain Scanner (Bumblebee integration). Scans developer endpoint…, Locate bumblebee binary., Scan with Bumblebee and convert to GSC findings., Detector, GSC Detector System — plugin architecture for security findings. Inspired by…, Detector interface — mirrors CVE Lite's DetectorFn. (+1 more)

### Community 14 - ".get_source_files"
Cohesion: 0.19
Nodes (7): Path, Check if file is a test/demo/fixture file., Check if file is not source code (images, fonts, media, lockfiles)., Return files matching glob relative to project root., Return all source files, optionally filtered by extension., Return source files, excluding tests and non-code files., Read file content with caching.

### Community 15 - "db_encrypt.py"
Cohesion: 0.22
Nodes (12): decrypt_db(), decrypt_on_open(), encrypt_db(), encrypt_on_close(), _get_key(), is_encrypted(), Transparent encrypt after operations., Get or create encryption key. (+4 more)

### Community 16 - "test_corpus.py"
Cohesion: 0.38
Nodes (12): check(), has_finding(), run_corpus(), scan_file(), test_assert_in_prod(), test_bare_except(), test_clean_code(), test_eval() (+4 more)

### Community 17 - "batch_and_override.py"
Cohesion: 0.22
Nodes (10): bulk_create_orders(), bulk_update_tickets(), parse_method(), Test: batch operations + HTTP method override (Gen+Eval approved patterns).…, VULN: bulk_update without checking all tickets belong to request.user.org., VULN: bulk_create without checking org ownership., VULN: _method override bypass., OK: checks ownership before bulk_update. (+2 more)

### Community 18 - "django_cross_org.py"
Cohesion: 0.18
Nodes (10): admin_ticket_list(), enumerate_tickets(), Test: Django IDOR + BAC — cross-tenant, admin panel, sequential enumeration.…, VULN: Direct PK lookup without ownership OR org/tenant check., VULN: Admin view without @staff_member_required., VULN: Sequential ID iteration — ticket enumeration., OK: Has ownership + org check., secure_ticket_detail() (+2 more)

### Community 19 - "gs005_sql_injection.py"
Cohesion: 0.22
Nodes (10): _count_sql_keywords(), detect(), _detect_line(), _has_user_input_nearby(), Path, GS005 — SQL/NoSQL Injection Patterns in Source Code. Detects: - String…, Check if user-input source exists within `window` chars after the match., Count SQL keywords in a line — for filtering noise. (+2 more)

### Community 20 - "Finding"
Cohesion: 0.24
Nodes (7): dict, detect(), GS010 — Weak SSH Configuration Detector Echelon: 2 (SECURITY) Category:…, detect(), GS013 — GraphQL Security Detector Echelon: 2 (SECURITY) Category: HIGH Detects…, Finding, Typed finding result. Backward-compatible with existing dict findings.

### Community 21 - "llm_verify.py"
Cohesion: 0.27
Nodes (9): _call_llm(), _extract_context(), _get_llm_client(), GSC LLM Verifier — deep analysis of findings using LLM context awareness. Takes…, Verify a finding using LLM context analysis. Returns updated finding with…, Get LLM client from Hermes environment (DeepSeek or configured provider)., Call LLM API for verification., Extract surrounding code context from a file. (+1 more)

### Community 22 - "gsc_github_dorks.py"
Cohesion: 0.25
Nodes (8): get_token(), list_dorks(), Поиск по GitHub Search API., Сканировать организацию по всем доркам., Показать список дорков., Получить GitHub токен из env или gh CLI., scan_org(), search_github()

### Community 23 - "framework_filter"
Cohesion: 0.31
Nodes (8): filter_findings(), framework_filter(), get_imports(), Apply framework filter to all findings. Returns filtered list., Extract all imported modules from a Python file using AST., Check if file should be skipped: tests, docs, examples, etc., Apply framework-aware filtering to a finding. Returns None if finding should be…, should_skip_file()

### Community 24 - "extension.js"
Cohesion: 0.25
Nodes (7): activate(), { execSync }, fs, getGscPath(), os, path, vscode

### Community 25 - "gs008_dead_code.py"
Cohesion: 0.32
Nodes (7): _count_occurrences(), detect(), _extract_constants(), GS008 — Dead code: declared but never used. Detects: - Module-level UPPER_CASE…, Extract module-level UPPER_CASE assignments with line numbers., Count whole-word occurrences of name in source., Find dead code in Python source files.

### Community 26 - "gsc_issue.py"
Cohesion: 0.25
Nodes (6): create_jira(), create_linear(), print_markdown(), Print a ready-to-paste markdown ticket., Create Jira ticket via REST API., Create Linear issue via GraphQL API.

### Community 27 - "TicketController"
Cohesion: 0.33
Nodes (3): Controller, TicketController, Request

### Community 28 - "_cron_collect.py"
Cohesion: 0.52
Nodes (6): collect_github(), collect_nvd(), export_obsidian(), main(), Insert into patterns + findings tables (schema-aware)., save_pattern_and_finding()

### Community 29 - "gs002_world_readable.py"
Cohesion: 0.33
Nodes (6): detect(), _is_sensitive(), Path, GS002 — World-readable files. Detects files with overly permissive permissions…, Check if file matches sensitive patterns., Check file permissions for sensitive files.

### Community 30 - "gs003_debug_prints.py"
Cohesion: 0.33
Nodes (6): detect(), _is_test_file(), Path, GS003 — Debug / diagnostic code left in production. Detects print(),…, Delegate to AuditContext's file classification., Find debug/diagnostic statements in production code.

### Community 31 - "gsc_export_knowledge.py"
Cohesion: 0.29
Nodes (6): export_jsonl(), export_jsonl_simple(), export_markdown(), Export as OpenAI fine-tuning format — system/user/assistant triples., Export as simple JSONL rows — compact, good for bulk training., Export as human-readable Markdown report.

### Community 32 - "post_pr_comment"
Cohesion: 0.38
Nodes (6): format_pr_comment(), get_pr_findings(), post_pr_comment(), Get top CRITICAL+HIGH findings for PR comment., Format findings as a GitHub PR review comment., Post findings as a PR comment via GitHub API.

### Community 33 - "analyze_reachability"
Cohesion: 0.38
Nodes (6): analyze_reachability(), build_import_graph(), is_reachable(), Check if a file is imported by any other file (reachable)., Add reachability info to findings. Unreachable → downgrade severity., Build a directed graph: file → set of files it imports.

### Community 34 - "check_source_driven"
Cohesion: 0.33
Nodes (6): check_source_driven(), infer_lang_from_title(), lang_to_rg_types(), Infer language from pattern title (e.g. 'Java: SQL injection' → 'java')., Convert language name to ripgrep -t type string., Echelon 1: Source-driven checks.

### Community 35 - "cmd_triage"
Cohesion: 0.33
Nodes (6): cmd_triage(), Interactive finding review — y/n/i/$/q + bulk mode., Group findings by pattern — accept/reject entire clusters at once., Bulk triage from stdin JSON., triage_bulk(), triage_by_pattern()

### Community 36 - "gs001_hardcoded_secret.py"
Cohesion: 0.40
Nodes (5): detect(), _is_placeholder(), GS001 — Hardcoded secrets in source code. Detects common patterns: API keys,…, Filter out obvious placeholder values., Scan all source files for hardcoded secrets.

### Community 37 - "gs007_idor.py"
Cohesion: 0.40
Nodes (5): detect(), _get_fix_suggestion(), GS007 — Broken Access Control: IDOR + BAC patterns. Detects: - Direct object…, Detect IDOR + BAC patterns — object references without auth checks., Return context-aware fix suggestion based on pattern type.

### Community 38 - "gs014_credential_exposure.py"
Cohesion: 0.40
Nodes (5): detect(), _match_glob(), Path, GS014 — Credential Exposure Detector Echelon: 2 (SECURITY) Category: HIGH…, Simple glob matching for credential file patterns.

### Community 39 - "gs016_linux_priv_esc.py"
Cohesion: 0.40
Nodes (5): _check_line(), detect(), GS016 — Linux Privilege Escalation Paths Detector Echelon: 2 (SECURITY)…, Detect privilege escalation paths in shell scripts, configs, playbooks., Check a single line against all patterns.

### Community 40 - "gsc_config.py"
Cohesion: 0.60
Nodes (5): cmd_init(), cmd_set(), cmd_show(), load(), save()

### Community 41 - "gsc_baseline.py"
Cohesion: 0.40
Nodes (4): baseline_apply(), baseline_save(), Save current open findings as baseline., Apply baseline: mark known findings so they don't show in scans.

### Community 42 - "cmd_patterns"
Cohesion: 0.50
Nodes (4): cmd_patterns(), cmd_patterns_review(), Show patterns needing manual review (auto-created, inactive)., Manage patterns — list/review/export/import.

### Community 44 - "generate_seed_patterns"
Cohesion: 0.50
Nodes (4): generate_seed_patterns(), Generate and seed patterns into DB., Generate OWASP/CWE/Python seed patterns., seed_patterns()

## Knowledge Gaps
- **33 isolated node(s):** `Ticket`, `express`, `app`, `gsc`, `vscode` (+28 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AuditContext` connect `AuditContext` to `gs001_hardcoded_secret.py`, `Path`, `gs007_idor.py`, `gs014_credential_exposure.py`, `gsc.py`, `gs016_linux_priv_esc.py`, `gs009_supply_chain.py`, `.get_source_files`, `gs005_sql_injection.py`, `Finding`, `gs008_dead_code.py`, `gs002_world_readable.py`, `gs003_debug_prints.py`?**
  _High betweenness centrality (0.077) - this node is a cross-community bridge._
- **Why does `Finding` connect `Finding` to `gs001_hardcoded_secret.py`, `gs007_idor.py`, `AuditContext`, `gs014_credential_exposure.py`, `gsc.py`, `gs016_linux_priv_esc.py`, `gs009_supply_chain.py`, `gs005_sql_injection.py`, `gs008_dead_code.py`, `gs002_world_readable.py`, `gs003_debug_prints.py`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **Why does `FileStateManager` connect `FileStateManager` to `gsc.py`, `cmd_scan`, `main`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Are the 6 inferred relationships involving `VulnerabilityItem` (e.g. with `GscDatabasePipeline` and `JsonExportPipeline`) actually correct?**
  _`VulnerabilityItem` has 6 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Ticket`, `express`, `app` to the rest of the system?**
  _33 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `VulnerabilityItem` be split into smaller, more focused modules?**
  _Cohesion score 0.050072568940493466 - nodes in this community are weakly interconnected._
- **Should `package.json` be split into smaller, more focused modules?**
  _Cohesion score 0.05555555555555555 - nodes in this community are weakly interconnected._