#!/usr/bin/env python3
"""
GSC Deep Reducer v1 — AI-first semantic vulnerability scanner.
Replaces regex with LLM: feeds code → DeepSeek analyzes → structured findings.

Usage: python3 gsc_deep_reducer.py <file-or-dir> [--model deepseek-chat] [--confidence 60]
"""
import os, sys, json, hashlib, sqlite3, argparse, re, fnmatch, time
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
API_URL = "https://api.deepseek.com/v1/chat/completions"
MAX_CHUNK_LINES = 200
MAX_FILE_SIZE = 100_000  # 100KB

# Ignored patterns
IGNORE_PATTERNS = [
    "*.min.js", "*.min.css", "*.map", "*.pyc", "*.pyo",
    "*.so", "*.dll", "*.exe", "*.bin", "*.zip", "*.tar*",
    "*.gz", "*.jpg", "*.png", "*.svg", "*.ico", "*.woff*",
    "*.ttf", "*.eot", "node_modules/**", ".git/**",
    "__pycache__/**", "*.egg-info/**", "dist/**", "build/**",
    "vendor/**", "package-lock.json", "*.lock", "poetry.lock",
    "Pipfile.lock", "*.sum", "go.sum",
]
IGNORE_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", 
               "dist", "build", "vendor", ".tox", ".eggs"}

SYSTEM_PROMPT = """You are a world-class application security researcher. Analyze the following code for security vulnerabilities with SEMANTIC understanding — not pattern matching.

## What to look for (by threat category):

### CRITICAL
- **Injection**: SQL/NoSQL/Command/LDAP/XPATH injection where user input reaches interpreter
- **SSRF**: User-controlled URLs fetched without validation (look for requests.get(url), fetch(), urllib)
- **Authentication Bypass**: Missing auth checks, hardcoded credentials, broken session management
- **Path Traversal**: User input in file paths without sanitization (open(user_input), os.path.join with user data)
- **Code Injection**: eval(), exec(), new Function(), pickle.loads() with user data
- **Deserialization**: Unsafe pickle/yaml.load/marshal with untrusted data

### HIGH
- **XSS**: Unsanitized data in HTML output, innerHTML, dangerouslySetInnerHTML
- **CORS Misconfig**: Access-Control-Allow-Origin: * with credentials
- **Weak Cryptography**: MD5/SHA1 for passwords, hardcoded keys/IVs, ECB mode
- **Information Disclosure**: Stack traces to users, debug mode in production, secrets in logs
- **Missing CSRF Protection**: State-changing operations without CSRF tokens
- **Open Redirect**: User-controlled redirect URLs

### MEDIUM
- **Insecure Defaults**: Debug=True, admin/admin credentials, default API keys
- **Race Conditions**: TOCTOU on file/DB operations without proper locking
- **Resource Exhaustion**: Unbounded uploads, uncontrolled recursion, missing rate limits
- **Log Injection**: User data in log messages without sanitization (CRLF injection)

## Output format (JSON only, no markdown):
{
  "findings": [
    {
      "title": "Short description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "cwe": ["CWE-89"],
      "line_start": N,
      "line_end": N,
      "vulnerable_code": "the exact vulnerable lines",
      "explanation": "Why this is vulnerable",
      "remediation": "How to fix"
    }
  ]
}

## Rules:
1. ONLY report REAL vulnerabilities — not style issues, not theoretical concerns
2. If the code is safe, return {"findings": []}
3. Consider context: is input sanitized? is there a WAF? is this a test file?
4. Rate your confidence honestly: 90+ for confirmed, 70-89 for likely, 50-69 for possible
5. Output ONLY the JSON, no explanation text
"""


def load_api_key():
    env_path = os.path.expanduser("~/.hermes/.env")
    with open(env_path) as f:
        for line in f:
            if line.startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def should_skip(filepath: str) -> bool:
    """Check if file should be skipped."""
    for pattern in IGNORE_PATTERNS:
        if fnmatch.fnmatch(filepath, pattern) or fnmatch.fnmatch(os.path.basename(filepath), pattern):
            return True
    parts = Path(filepath).parts
    for part in parts:
        if part in IGNORE_DIRS:
            return True
    return False


def chunk_code(content: str, filepath: str, start_line: int = 1) -> list:
    """Split large files into overlapping chunks."""
    lines = content.split('\n')
    if len(lines) <= MAX_CHUNK_LINES:
        return [{
            "filepath": filepath,
            "start_line": start_line,
            "content": content,
        }]
    
    chunks = []
    overlap = 20
    i = 0
    while i < len(lines):
        chunk_lines = lines[i:i + MAX_CHUNK_LINES]
        chunks.append({
            "filepath": filepath,
            "start_line": start_line + i,
            "content": '\n'.join(chunk_lines),
        })
        i += MAX_CHUNK_LINES - overlap
    return chunks


def analyze_chunk(chunk: dict, api_key: str, model: str) -> dict:
    """Send code chunk to DeepSeek for security analysis."""
    user_prompt = f"""File: {chunk['filepath']} (lines {chunk['start_line']}-{chunk['start_line'] + len(chunk['content'].split(chr(10))) - 1})

```{Path(chunk['filepath']).suffix[1:] or 'text'}
{chunk['content']}
```

Analyze this code for security vulnerabilities."""
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
        "stream": False,
    }
    
    req = Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    
    try:
        with urlopen(req, timeout=120) as resp:
            response = json.loads(resp.read())
    except HTTPError as e:
        return {"error": f"API error {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)}
    
    content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
    
    # Extract JSON from response (model might wrap in markdown)
    json_match = re.search(r'\{[\s\S]*"findings"[\s\S]*\}', content)
    if not json_match:
        return {"findings": [], "raw_response": content[:500]}
    
    try:
        result = json.loads(json_match.group())
    except json.JSONDecodeError:
        return {"findings": [], "raw_response": content[:500]}
    
    return result


def find_files(target_path: str) -> list:
    """Recursively find code files to analyze."""
    extensions = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', 
                  '.rs', '.rb', '.php', '.c', '.cpp', '.h', '.hpp',
                  '.cs', '.swift', '.kt', '.scala', '.sh', '.bash',
                  '.yaml', '.yml', '.tf', '.dockerfile', '.sql'}
    
    target = Path(target_path)
    if target.is_file():
        return [str(target)] if target.suffix in extensions else []
    
    files = []
    for root, dirs, filenames in os.walk(target):
        # Skip ignored dirs
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for f in filenames:
            fp = os.path.join(root, f)
            if not should_skip(fp) and Path(f).suffix in extensions:
                if os.path.getsize(fp) < MAX_FILE_SIZE:
                    files.append(fp)
    return files


def save_to_db(findings: list, project: str, run_id: str):
    """Save AI findings to GSC database."""
    db = sqlite3.connect(DB)
    now = datetime.now(timezone.utc).isoformat()
    
    for f in findings:
        fp = hashlib.sha256(
            f"{f.get('title','')}|{json.dumps(f.get('cwe',['']))}|{f.get('file_path','')}|{f.get('line_start',0)}".encode()
        ).hexdigest()[:16]
        
        db.execute("""
            INSERT OR IGNORE INTO findings 
            (project, category, title, file_path, line_number, detail,
             pattern_id, echelon, status, created_at, run_id,
             revalidation_verdict, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?,
                    ?, ?)
        """, (
            project,
            f.get('severity', 'MEDIUM'),
            f.get('title', 'Untitled'),
            f.get('file_path', ''),
            f.get('line_start', 0),
            json.dumps({
                'cwe': f.get('cwe', []),
                'explanation': f.get('explanation', ''),
                'remediation': f.get('remediation', ''),
                'source': 'deep-reducer-ai',
            }),
            fp,
            3,  # echelon: AI-generated
            now,
            run_id,
            None,  # Not revalidated yet
            f.get('confidence', 50),
        ))
    db.commit()
    db.close()


def main():
    parser = argparse.ArgumentParser(description="GSC Deep Reducer — AI-first security scanner")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--model", default="deepseek-chat", help="Model (default: deepseek-chat)")
    parser.add_argument("--confidence", type=int, default=50, help="Min confidence (default: 50)")
    parser.add_argument("--dry-run", action="store_true", help="Don't save to DB")
    parser.add_argument("--limit", type=int, default=20, help="Max files to analyze (default: 20)")
    args = parser.parse_args()
    
    api_key = load_api_key()
    if not api_key:
        print("❌ DEEPSEEK_API_KEY not found")
        sys.exit(1)
    
    target = os.path.abspath(args.target)
    files = find_files(target)
    print(f"🔍 Found {len(files)} files to analyze")
    
    if len(files) > args.limit:
        # Prioritize: smaller files first, interesting extensions
        files.sort(key=lambda f: (os.path.getsize(f), Path(f).suffix != '.py'))
        files = files[:args.limit]
        print(f"   Limited to {args.limit} files")
    
    run_id = f"dr-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    all_findings = []
    total_chunks = 0
    
    for i, filepath in enumerate(files):
        try:
            with open(filepath, errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"  ⚠️ Cannot read {filepath}: {e}")
            continue
        
        chunks = chunk_code(content, filepath)
        total_chunks += len(chunks)
        
        for chunk in chunks:
            print(f"  🧠 [{i+1}/{len(files)}] {filepath}:{chunk['start_line']} ({len(chunk['content'].split(chr(10)))} lines)", end=" ")
            result = analyze_chunk(chunk, api_key, args.model)
            
            if "error" in result:
                print(f"❌ {result['error'][:60]}")
                continue
            
            findings = result.get("findings", [])
            for f_item in findings:
                if f_item.get("confidence", 0) >= args.confidence:
                    # Adjust line numbers relative to file
                    f_item["line_start"] = f_item.get("line_start", 0) + chunk["start_line"] - 1
                    f_item["line_end"] = f_item.get("line_end", 0) + chunk["start_line"] - 1
                    f_item["file_path"] = filepath
                    f_item["project"] = os.path.basename(os.path.dirname(target)) or os.path.basename(target)
                    all_findings.append(f_item)
            
            print(f"→ {len(findings)} candidates")
            time.sleep(0.5)  # Rate limit
    
    print(f"\n{'='*60}")
    print(f"📊 Deep Reduce complete: {total_chunks} chunks analyzed")
    print(f"   Findings: {len(all_findings)} (confidence ≥ {args.confidence}%)")
    
    if all_findings:
        critical = [f for f in all_findings if f['severity'] == 'CRITICAL']
        high = [f for f in all_findings if f['severity'] == 'HIGH']
        print(f"   CRITICAL: {len(critical)}, HIGH: {len(high)}")
        
        print("\n🔴 CRITICAL:")
        for f in critical[:5]:
            print(f"   {f['title']}")
            print(f"   📁 {f['file_path']}:{f['line_start']} | CWE: {f.get('cwe',[])} | conf: {f['confidence']}%")
        
        if not args.dry_run and all_findings:
            project_name = os.path.basename(os.path.abspath(target))
            save_to_db(all_findings, project_name, run_id)
            print(f"\n💾 Saved {len(all_findings)} findings to DB (run: {run_id})")
    else:
        print("   ✅ No vulnerabilities found")
    
    return all_findings


if __name__ == "__main__":
    main()
