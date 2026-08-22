"""GSC Enterprise Agent — сканер в инфраструктуре клиента.

Модель: агент сканирует локальные репо по расписанию,
сохраняет findings локально, отправляет в облако batch'ами.
Код НИКОГДА не покидает периметр клиента.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from agent.cache import FindingCache
from agent.policy import PolicySync
from agent.registry import AgentRegistry


class AgentRunner:
    def __init__(self, tenant_key: str, repos_dir: str,
                 interval: int = 3600, cloud_url: str = None,
                 air_gap: bool = False):
        self.tenant_key = tenant_key
        self.repos_dir = Path(repos_dir)
        self.interval = interval
        self.cloud_url = cloud_url or os.environ.get(
            "GSC_CLOUD_URL", "https://cloud.gsc.dev")
        self.air_gap = air_gap
        self.cache = FindingCache(Path.home() / ".gsc-agent/cache")
        self.registry = AgentRegistry(self.cloud_url, tenant_key)
        self.policy = PolicySync(self.cloud_url, tenant_key)

    def run_forever(self):
        agent_id = self.registry.activate()
        print(f"[agent] activated: {agent_id}", flush=True)
        while True:
            try:
                self._scan_cycle(agent_id)
            except Exception as e:
                print(f"[agent] cycle error: {e}", flush=True)
            time.sleep(self.interval)

    def _scan_cycle(self, agent_id: str):
        repos = self._discover_repos()
        policies = self.policy.fetch() if not self.air_gap else {}

        if not self.air_gap:
            self._flush_cache(agent_id)

        for repo_path in repos:
            report = self._scan_repo(repo_path, policies)
            if report is None:
                continue
            self.cache.store(repo_path.name, report)
            if not self.air_gap:
                self._ingest(agent_id, repo_path.name, report)

    def _flush_cache(self, agent_id: str):
        for repo_name in self.cache.get_unsynced():
            report = self.cache.load(repo_name)
            if report:
                try:
                    self._ingest(agent_id, repo_name, report)
                except Exception:
                    break

    def _discover_repos(self) -> list[Path]:
        return sorted(
            p for p in self.repos_dir.iterdir()
            if p.is_dir() and (p / ".git").exists())

    def _scan_repo(self, repo_path: Path,
                   policies: dict) -> dict | None:
        with tempfile.TemporaryDirectory(prefix="gsc_agent_") as tmp:
            report_path = os.path.join(tmp, "report.json")
            cmd = ["gsc", "external-scan", str(repo_path),
                   "--profile", policies.get("profile", "audit"),
                   "-o", report_path]
            if policies.get("with_poc"):
                cmd.append("--with-poc")
            if policies.get("with_chains"):
                cmd.append("--with-chains")
            env = {**os.environ,
                   "GSC_DB_PATH": os.path.join(tmp, "agent.db"),
                   "HOME": tmp}
            proc = subprocess.run(cmd, env=env, timeout=1800,
                                  capture_output=True, text=True)
            if proc.returncode not in (0, 1):
                print(f"[agent] scan failed: {repo_path.name}: "
                      f"{proc.stderr[-300:]}", flush=True)
                return None
            with open(os.path.join(report_path, "scan.json"), encoding="utf-8") as f:
                return json.load(f)

    def _ingest(self, agent_id: str, repo_name: str, report: dict):
        findings = report.get("findings", [])
        chains = report.get("chains", [])
        mutations = report.get("mutation_alerts", [])
        payload = {
            "agent_id": agent_id,
            "repo": repo_name,
            "findings": findings,
            "chains": chains,
            "mutation_alerts": mutations,
            "usage": report.get("usage", {}),
        }
        try:
            self.registry.ingest(payload)
            self.cache.mark_synced(repo_name)
        except Exception as e:
            print(f"[agent] ingest failed (cached): {e}", flush=True)


def main():
    import argparse
    p = argparse.ArgumentParser(prog="gsc-agent")
    p.add_argument("--tenant-key", required=True)
    p.add_argument("--repos", required=True)
    p.add_argument("--interval", type=int, default=3600)
    p.add_argument("--cloud-url", default=None)
    p.add_argument("--air-gap", action="store_true")
    p.add_argument("--once", action="store_true",
                   help="Один цикл и выход (для cron)")
    args = p.parse_args()
    runner = AgentRunner(args.tenant_key, args.repos, args.interval,
                         args.cloud_url, args.air_gap)
    if args.once:
        agent_id = runner.registry.activate()
        runner._scan_cycle(agent_id)
    else:
        runner.run_forever()


if __name__ == "__main__":
    main()