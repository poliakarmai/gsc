# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""GitHub-режим worker'а (S2).

Пайплайн: installation token → клон (netrc, не argv) → checkout head_sha
→ gsc external-scan (fork-safe для форков) → инжест с историей (мутации,
цепочки, авто-resolve) → комментарий + check run через адаптер v0.23.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

from cloud.github_auth import get_installation_token, gh_headers
from cloud.mutations_cloud import ingest_with_history
from cloud.publish import publish_pr_result


def clone_repo(clone_url: str, head_sha: str, tmp: str) -> str:
    src = os.path.join(tmp, "src")
    # Токен в $HOME/.netrc (chmod 600), НЕ в argv — не виден в ps
    netrc = os.path.join(tmp, ".netrc")
    token = None
    if clone_url.startswith("https://github.com/"):
        token = os.environ.get("_CURRENT_INSTALL_TOKEN", "")
        with open(netrc, "w") as fh:
            fh.write(f"machine github.com login x-access-token "
                     f"password {token}\n")
        os.chmod(netrc, 0o600)
    env = {**os.environ, "HOME": tmp}
    subprocess.run(["git", "clone", "--quiet", "--depth", "100",
                    clone_url, src], env=env, check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", src, "checkout", "--quiet", head_sha],
                   env=env, check=True, capture_output=True)
    return src


def run_scan(job: dict, src: str, tmp: str) -> dict:
    report_path = os.path.join(tmp, "report.json")
    cmd = ["gsc", "external-scan", src,
           "--profile", job["profile"],
           "--mode", "diff",
           "--base", f"origin/{job['pr']['base_ref']}",
           "--head", "HEAD",
           "-o", report_path]
    if job["pr"]["is_fork"]:
        cmd.append("--no-llm")          # fork-safe: regex-only
    else:
        cmd += ["--with-poc", "--with-chains"]
    env = {**os.environ,
           "HOME": tmp,
           "GSC_DB_PATH": os.path.join(tmp, "worker.db")}
    proc = subprocess.run(cmd, env=env, timeout=900,
                          capture_output=True, text=True)
    if proc.returncode not in (0, 1):   # 1 = blocking — нормальный исход
        raise RuntimeError(proc.stderr[-500:] or "scanner failed")
    with open(report_path, encoding="utf-8") as f:
        return json.load(f)


def process_github_job(job: dict) -> None:
    token = get_installation_token(job["installation_id"])
    os.environ["_CURRENT_INSTALL_TOKEN"] = token
    try:
        with tempfile.TemporaryDirectory(prefix="gsc_gh_") as tmp:
            src = clone_repo(job["repo"]["clone_url"],
                             job["pr"]["head_sha"], tmp)
            report = run_scan(job, src, tmp)
            ingest_with_history(job, report)
            publish_pr_result(job, report,
                              gh_headers(job["installation_id"]))
    finally:
        os.environ.pop("_CURRENT_INSTALL_TOKEN", None)