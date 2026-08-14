"""tests/test_cloud_s2.py — SaaS S2: workers + job queue (INTEGRATION)."""
import os
import sys

# GSC-005: integration test — requires a live PostgreSQL. Skip gracefully when
# no DB is configured (no module-level sys.exit, which breaks pytest collection).
_HAS_DB = bool(os.environ.get("GSC_DATABASE_URL"))

if _HAS_DB:
    import json
    import subprocess
    import tempfile

    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, '.')

    from cloud.workers import (
        enqueue_scan, get_next_job, complete_job, get_job_status,
        get_tenant_jobs, scan_repo,
    )

    passed = 0
    failed = 0

    def run_case(name, fn, expect=True):
        global passed, failed
        try:
            result = fn()
            assert result is not False
            passed += 1
            print(f'  ✅ {name}')
        except Exception as e:
            failed += 1
            print(f'  ❌ {name}: {e}')

    def t1():
        jid = enqueue_scan("tenant_s2_test", "/tmp/test_repo")
        assert len(jid) == 12
        return True

    def t2():
        job = get_next_job()
        assert job is not None and job.tenant_id == "tenant_s2_test"
        complete_job(job.job_id, [{"rule_id": "GS020", "title": "XSS"}], "")
        return True

    def t3():
        jid = enqueue_scan("tenant_s2_test", "/tmp/t3")
        job = get_next_job()
        assert job is not None
        complete_job(job.job_id, [], "scan failed: timeout")
        status = get_job_status(job.job_id)
        assert status and status["status"] == "failed" and status["error"] == "scan failed: timeout"
        return True

    def t4():
        jobs = get_tenant_jobs("tenant_s2_test")
        assert len(jobs) >= 2  # t2 + t3
        return True

    def t5():
        # Real scan of a calibration project
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "app.py"), "w") as f:
            f.write("x = 1\n")
        findings, err = scan_repo(d)
        assert err == "" and isinstance(findings, list)
        return True

    def t6():
        # Empty queue returns None
        jid = enqueue_scan("t6", "/tmp/t6")
        job = get_next_job()
        complete_job(job.job_id, [], "")
        assert get_next_job() is None  # queue drained
        return True

    run_case("enqueue returns job_id", t1)
    run_case("get_next_job + complete_job", t2)
    run_case("failed job retains error", t3)
    run_case("get_tenant_jobs lists all", t4)
    run_case("scan_repo on calib project", t5)
    run_case("empty queue → None", t6)

    print(f'\n{"="*40}\n{passed} passed, {failed} failed')

if __name__ == "__main__":
    if not _HAS_DB:
        print("  SKIP: test_cloud_s2 requires GSC_DATABASE_URL (PostgreSQL)")
        sys.exit(0)
    sys.exit(0 if failed == 0 else 1)
