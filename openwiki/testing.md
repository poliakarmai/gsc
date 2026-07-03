# Testing

GSC uses corpus-based testing — snippets of vulnerable/clean code are scanned and the JSON output is checked for expected findings.

## Test Framework

Tests live in `/tests/test_corpus.py` and use a `scan_file()` helper that:

1. Creates a temporary directory
2. Writes the code snippet to a file
3. Initializes a git repo (GSC requires git context)
4. Runs `gsc scan <dir> --ci --json`
5. Returns parsed JSON findings
6. Cleans up the temp directory

The helper supports custom filenames and permissions (for world-readable file tests).

## Current Tests (8)

| Test | What it checks | Expected |
|------|---------------|----------|
| `test_sql_injection` | f-string in SQL query | CRITICAL finding |
| `test_hardcoded_secret` | Password + GitHub token in source | Any finding |
| `test_unsafe_pickle` | `pickle.loads()` usage | CRITICAL finding |
| `test_bare_except` | Bare `except:` clause | MEDIUM finding |
| `test_eval` | `eval()` function call | HIGH finding |
| `test_world_readable_env` | World-readable `.env` with secrets | HIGH finding |
| `test_clean_code` | Clean function with no vulnerabilities | No CRITICAL findings (FP check) |
| `test_assert_in_prod` | `assert` statement in production code | MEDIUM finding |

## Running Tests

```bash
# pytest (recommended)
python3 -m pytest tests/test_corpus.py -v

# Legacy mode
python3 tests/test_corpus.py
```

Output format:
```
==================================================
GSC Corpus Tests
==================================================

── SQL injection ──
  ✅ SQL injection
── Hardcoded secret ──
  ✅ Hardcoded secret
...
Results: 8/8 passed
```

## Adding a New Test

1. Add a pytest-compatible function in `/tests/test_corpus.py`:

```python
def test_my_detector():
    findings = scan_file('vulnerable_code_here\n')
    assert has_finding(findings, "keyword", "SEVERITY")
```

2. Optionally add multi-file corpus in `/corpus/` (see existing: `corpus_gs005_*.py`, etc.)

3. Run tests: `python3 -m pytest tests/test_corpus.py -v`

## How Tests Work Internally

The `scan_file()` function (`/tests/test_corpus.py:16-35`):

```python
def scan_file(code: str, filename: str = "test.py", chmod: str = None) -> list[dict]:
    d = tempfile.mkdtemp()
    try:
        fpath = Path(d) / filename
        fpath.write_text(code)
        if chmod:
            fpath.chmod(int(chmod, 8))
        subprocess.run(["git", "-C", d, "init", "-q"], capture_output=True)
        subprocess.run(["git", "-C", d, "add", "-A"], capture_output=True)
        subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], capture_output=True)
        r = subprocess.run(
            [sys.executable, GSC, "scan", d, "--ci", "--json"],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(r.stdout) if r.stdout.strip() else []
    except Exception as e:
        print(f"  scan_file error: {e}")
        return []
    finally:
        shutil.rmtree(d, ignore_errors=True)
```

## Corpus Directory

`/corpus/` contains multi-language corpus files (currently for GS005 SQL injection):
- `corpus_gs005_javascript.js`
- `corpus_gs005_php.php`
- `corpus_gs005_python.py`
- `corpus_gs005_ruby.rb`

These are larger test fixtures used by integration tests.

## Change Guidance

- **After modifying a detector**: Run all 8 corpus tests to confirm no regressions
- **After adding a detector**: Add at minimum one TP test and one clean-code FP test
- **After modifying the scan pipeline**: Run all tests + manually scan a known project for regression
- **If tests fail unexpectedly**: Check that `GSC` path in `test_corpus.py` points to the correct `/gsc.py` (default: `~/gsc/gsc.py`)
