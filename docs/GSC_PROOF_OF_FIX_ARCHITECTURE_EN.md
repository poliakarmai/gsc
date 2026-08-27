# Proof-of-Fix in GSC: An Architecture for Provable Vulnerability Remediation Verification

**Document version:** 2.0
**Date:** 2026-08-15
**Author:** Alexey Polyakov
**Product:** GSC (Git Security Checker) v1.4.0
**Status:** for review (technical audit incorporated)

---

## Abstract

GSC is a self-learning AppSec platform implementing the full pipeline
`detect → prove → fix → verify → heal → predict`. Its defining feature is
**Proof-of-Fix (PoF)**: a mechanism that does not *suggest* a fix but **proves**
it. This paper describes the PoF architecture not as a list of modules but as
**three architectural contracts** — markers, isolation, and verification — that
collapse into a single formula and define exactly what the `verified` verdict
guarantees. It also shows why competitors (Snyk CodeFix, Veracode Fix) stop at
"assumption" while PoF reaches "fact".

**Keywords:** SAST, Proof-of-Fix, architectural contracts, PoC generation,
sandbox isolation, fail-closed, verified remediation.

---

## 1. Introduction

### 1.1 The problem: "fixed" ≠ "proven"

Classical SAST solves *detection*: it locates a suspicious site and emits a
finding. The rest is manual. A fundamental gap remains:

- **The finding may be a false positive** — the pattern matched, no flaw exists.
- **The fix may be incomplete** — one vector closed, a neighboring one still open.
- **"Closed" is not proven** — a tracker status is not proof of non-exploitation.

The result is expensive manual triage, a growing pile of unverified findings,
alert fatigue, and — at the limit — a real vulnerability lost in the noise.

### 1.2 What GSC proposes

GSC appends a *proof* phase to detection: for every finding it generates a PoC
(code that *exploits* the flaw), generates a patch, **runs the PoC against both
code versions in a sandbox**, and records the verdict: exploitation happened
before, and does not happen after. Only that exact match yields `verified`.

### 1.3 Why competitor patch generation is not enough

To see the value of PoF, one principle difference suffices: competitors stop at
patch *generation*; PoF proceeds to *verification*.

**Snyk CodeFix** emits a fix as a diff but **does not verify the diff actually
eliminates the flaw**. For SQL injection it may propose a parameterized query
`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`. But if
`user_id` still arrives from an unsanitized source and is not taint-tracked end
to end, the fix remains incomplete — CodeFix does not execute the code to find
out.

**Veracode Fix** proposes point replacements (e.g. `eval(user_input)` →
`JSON.parse(user_input)`) but **does not post-verify** that `user_input` is now
valid and free of exploitable constructs (nested SSRF, ReDoS in the parser). No
execution check is performed — the tool trusts the proposed replacement.

**The key takeaway:**

> Patch generation is an **assumption**. Verification through a repeated PoC is a
> **fact**. GSC moves from assumption to fact: a patch counts as fixed only when
> the exploit that *reproduced* the flaw *stops firing* against the patched code.

---

## 2. Proof-of-Fix as an architectural contract

PoF reliability is defined not by a set of modules but by **three architectural
contracts**. They — not implementation syntax — are the essence of the
architecture.

### 2.1 The marker contract

A PoC must *prove* exploitation by printing one of the success markers:

```
VULNERABLE | EXPLOITED | PWNED | LEAKED | SUCCESS | BREACH
```

PoC success is recorded **only** when both conditions hold: `exit_code == 0`
**and** a marker is present in stdout. A zero exit code alone is not enough —
otherwise a PoC that merely "finished without error" would be wrongly treated as
exploiting. This contract guards against false positives.

### 2.2 The isolation contract

Every PoC execution happens in a sandbox with resource and network limits:
`RLIMIT_CPU`, `RLIMIT_AS`, `--network none`, `--read-only`, all capabilities
dropped (details in §4). The contract guarantees the PoC **cannot** read host
secrets, exhaust CI resources, or compromise the scanning environment.

### 2.3 The verification contract

A fix is accepted as successful **only** on the exact match:

```
poc_before_success == True   AND   poc_after_success == False
```

Any deviation — incomplete fix or false-positive finding — renders the result
unverified. This is the mathematical definition of `verified`.

### 2.4 The PoF formula

The three contracts collapse into one formula:

```
PoF_verified = (poc_before_success == True)
             ∧ (poc_after_success == False)
             ∧ is_container_isolation(before)
             ∧ is_container_isolation(after)
```

The third and fourth conjuncts are the **fail-closed gate**: `verified` is
admissible only when both stages ran in an OS-isolated container, not in a
degraded mode. Consequence:

> If PoF says `verified` — the vulnerability was reproduced and removed in a
> controlled environment, and no third-party code could have influenced the
> result.

---

## 3. System overview and PoF's place

### 3.1 The full GSC pipeline

```
detect ──► prove ──► fix ──► verify ──► heal ──► predict
```

| Phase | Purpose |
|---|---|
| **detect** | static analysis, 47 detectors |
| **prove** | PoC generation, exploitation confirmation |
| **fix** | patch generation (LLM) |
| **verify** | run PoC against before/after in a sandbox |
| **heal** | auto-remediation in CI (self-healing) |
| **predict** | predictive analytics over history |

Current core state: **47 detectors** (43 registry + 4 standalone engines:
Invariants GS028, Secrets GS029, SCA/OSV.dev GS030, IaC GS031), schema 33,
165 modules, ~494K findings in a SQLite DB, 426 tests across 75 files. Figures
are verified via `python3 gsc_meta.py`.

### 3.2 Data flow

```
finding + source
      │
      ▼
[PoC generation] ──► poc_code          (deterministic or LLM)
      │
      ▼
[Patch generation] ──► patch, up to MAX_ITERATIONS=3
      │
      ▼
[Sandbox]  PoC vs VULNERABLE code ──► poc_before_success
           PoC vs PATCHED code    ──► poc_after_success
      │
      ▼
[Fail-closed gate]  verification contract + OS-isolation
      │
      ▼
FixEvidence: verified | structural | syntax_only | failed
```

---

## 4. Isolated execution

Running a generated PoC is the **critical security boundary**: a PoC is, by
definition, malicious code. GSC addresses this with two-tier isolation.

### 4.1 Container isolation (primary path)

The PoC runs in a disposable container (Docker or Podman) with a strict flag set:

| Flag | Value | Guarantee |
|---|---|---|
| `--network none` | egress deny | the PoC cannot reach the network |
| `--read-only` | read-only rootfs | container filesystem is immutable |
| `--cap-drop ALL` | drop all capabilities | no kernel privileges |
| `--security-opt no-new-privileges` | no setuid | no privilege escalation |
| `--pids-limit 64` | process limit | no fork bomb |
| `--memory 512m` / `--cpus 1` | resource caps | no CPU/RAM exhaustion |
| `--user 65534:65534` | nobody UID | no root inside the container |
| `--tmpfs /tmp` + workdir mount | only workspace writable | writes confined to its own dir |

### 4.2 rlimit fallback (degradation)

Without a container runtime, the PoC runs as a subprocess with POSIX `rlimit`
(`RLIMIT_CPU` 30 s, `RLIMIT_AS` 512 MB, `RLIMIT_NPROC` 64, `RLIMIT_FSIZE` 16 MB,
`RLIMIT_NOFILE` 256). **Important:** rlimit is a *degradation*, not isolation; at
the fail-closed gate a result produced under rlimit is **never** labeled
`verified`.

### 4.3 Environment isolation

The PoC receives a whitelist of 9 environment variables instead of the full
`os.environ`, closing the host-secret leak (`DEEPSEEK_API_KEY`, `GITHUB_TOKEN`,
`JWT_SECRET`) into executed PoC code (finding DD-01 of an independent audit).

---

## 5. PoC and patch generation

### 5.1 PoC: deterministic + LLM

For common flaw classes (SQLi, command injection, IDOR, XSS, SSRF, open redirect,
and via title keywords — SSTI/pickle/XXE/path traversal) the PoC is generated
**without an LLM**, from strict templates. For the rest — via an LLM (60 s timeout). Without `DEEPSEEK_API_KEY` the system degrades to regex-only mode.
Each execution is bounded: 30 s, output ≤ 4096 bytes, network neutralized by a
`127.0.0.1:9` discard-port proxy.

### 5.2 Patch: minimality and atomicity

The patch is generated as a set of edit-instructions (`find`/`replace` pairs)
where `find` must match the file text exactly. This yields two properties
essential to reliability: the patch is **minimal** (reviewable) and **atomic** —
an inexact match discards the attempt wholesale rather than applying a mangled
patch. Up to 3 generation iterations and 6 edits per patch; a failed attempt is
passed back into the LLM context for the next one.

---

## 6. Verification cycle and fail-closed gate

### 6.1 before/after PoC

The proof core is a double run of one PoC:

1. **Before:** the PoC against *vulnerable* code → it **must trigger**. If not,
   likely a false positive; the verdict is rejected.
2. **After:** the PoC against *patched* code → it **must not trigger**. If it
   still does, the fix is incomplete; the verdict is rejected.

### 6.2 Fail-closed gate (GSC-001)

The final check: `verified` is admissible **only** when both stages used
OS-isolation. Otherwise the result is returned with an explicit reason, not a
false "verified". Deliberate: better to honestly say "not proven" than to emit an
unjustified signal.

### 6.3 Trust levels

| Level | Criterion | Meaning |
|---|---|---|
| `verified` | PoC triggered before, not after, both stages in a container | proven |
| `structural` | detector stopped firing on patched code | indirect |
| `syntax_only` | syntax intact, no proof | weak |
| `failed` | could not generate/apply/verify | none |

---

## 7. Security model and guarantees

### 7.1 Threat model

The threat is **hostile PoC code**. An attacker might try to read host secrets,
write to the filesystem, reach the network (SSRF/exfil), exhaust resources, or
escalate privileges.

### 7.2 Defense-in-depth

| Layer | Mechanism |
|---|---|
| Network | `--network none` (container) / proxy `127.0.0.1:9` (fallback) |
| Filesystem | `--read-only` rootfs, writes confined to workdir, `RLIMIT_FSIZE` |
| Privileges | `--cap-drop ALL`, `no-new-privileges`, nobody UID |
| Resources | `--pids-limit 64`, `--memory 512m`, `--cpus 1`, `RLIMIT_AS` |
| Secrets | env-whitelist (9 vars), never full `os.environ` |
| Trust | fail-closed gate: no container → no `verified` |

### 7.3 The `verified` guarantee

Together the contracts (§2) yield the following guarantee: **if PoF returns
`verified`, the vulnerability was factually reproduced by an exploit and
factually removed, in an environment from which the generated code could neither
read secrets nor influence the result**. This is PoF's real "product": trust
grounded in evidence, not declarations.

---

## 8. Current state and metrics

| Parameter | Value |
|---|---|
| Version | 1.4.0 |
| Detectors | 42 (43 registry + 4 standalone) |
| DB schema | 32 |
| Modules | 114 |
| Findings in DB | ~494K |
| Tests | 426 (75 files) |
| PoF iterations | up to 3, up to 6 edits per patch |
| PoC timeout | 30 s, output ≤ 4096 bytes |

---

## 9. Limitations

1. **Sandbox language support:** `verify_fix` runs Python PoCs only; other
   languages return `verified=False` with a reason.
2. **Container-runtime dependency:** without docker/podman the top trust level
   `verified` is unreachable — a deliberate fail-closed choice.
3. **LLM-dependent depth:** without `DEEPSEEK_API_KEY`, PoC/patch are generated
   only for templated classes.
4. **Single file per cycle:** PoF operates on a single file, not a whole
   repository; cross-module exploit chains are outside the current cycle.

---

## 10. Roadmap

- **Runtime Validator (IAST-lite):** verify by actual runtime exploitation —
  monkeypatch `subprocess`/`requests`/`open` in the sandbox venv, then `strace`
  (requires `SYS_PTRACE`), then Falco/Tetragon only in enterprise on-prem.
  **Never `--privileged`** — it breaks isolation (F-05) and turns PoF from a
  defense into an attack vector; any PoC requiring `--privileged` is
  automatically rejected.
- **JS/Go/Rust support** in `verify_fix`.
- **PostgreSQL + RLS** for multi-tenant SaaS (tenant isolation, DD-09).

---

## 11. Conclusion

Proof-of-Fix turns SAST from a "detector" into a "proven-remediation engine".
The core idea is **fail-closed**: the system would rather refuse to confirm a fix
than emit an unjustified `verified`. Architecturally this is expressed through
three contracts (markers, isolation, verification) and one formula — not a list
of modules. Combined with self-learning, the platform moves toward its goal:
making security *verifiable* rather than merely *declared*.

---

## Appendix A. Traceability (code ↔ claim map)

| Claim | File:lines |
|---|---|
| 47 detectors (38+4), schema 33, 165 modules | `gsc_meta.py` → `get_meta()` |
| Levels `verified/structural/syntax_only/failed` | `gsc_proofoffix.py:52`, `_classify()` ~476 |
| Exploitation markers | `gsc_pof_sandbox.py:21` |
| PoC timeout/limits | `gsc_proofoffix.py:31-34` |
| Network proxy stub | `gsc_proofoffix.py:37-43` |
| Container isolation flags | `gsc_pof_sandbox.py:230-244` |
| rlimit limits | `gsc_pof_sandbox.py:122-153` |
| env-whitelist (DD-01) | `gsc_pof_sandbox.py:36-40`, `gsc_proofoffix.py:133+` |
| before/after cycle + fail-closed (GSC-001) | `gsc_pof_sandbox.py:319-362` |
| LLM call | `gsc_proofoffix.py:205` |
| Deterministic PoC | `gsc_proofoffix.py:_generate_poc_code` ~492 |

*This document was generated from the actual code of `poliakarmai/gsc` (branch
`master`). All figures were verified by running `python3 gsc_meta.py` and reading
the sources.*
