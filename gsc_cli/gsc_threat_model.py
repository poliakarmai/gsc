#!/usr/bin/env python3
"""
GSC Threat Modeler — AI-first attack surface analysis.
Analyzes repo architecture before scanning to guide vulnerability discovery.

Pipeline: threat-model → deep-reduce → validate (GS024)

Usage: python3 gsc_threat_model.py <repo-path> [--quick]
"""
import os, sys, json, hashlib, argparse, re
from pathlib import Path
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError

API_URL = "https://api.deepseek.com/v1/chat/completions"

THREAT_MODEL_PROMPT = """You are a senior application security architect performing a threat modeling exercise.

Analyze this codebase and produce a structured threat model. Think like an attacker: what can be exploited?

## Analyze the following artifacts:

### 1. Repository Structure
- What does this project DO? (web app, API, CLI, library, mobile backend?)
- Key directories and their purposes
- Entry points: HTTP routes, API endpoints, CLI commands, file processors

### 2. Dependencies & Stack
- Framework (Django, Flask, Express, React, etc.)
- Database (PostgreSQL, MongoDB, Redis?)
- External services called (APIs, payment gateways, cloud services)
- Authentication mechanism (JWT, OAuth, sessions?)

### 3. Trust Boundaries (STRIDE)
For each boundary, list potential threats:

**Spoofing**: Can users impersonate others? Weak auth?
**Tampering**: Can data be modified in transit/storage? Missing integrity checks?
**Repudiation**: Actions without audit trail? Missing logging?
**Information Disclosure**: Sensitive data exposed? Debug endpoints? Verbose errors?
**Denial of Service**: Resource exhaustion? Missing rate limits? Infinite loops?
**Elevation of Privilege**: Can users escalate roles? Missing authorization checks?

### 4. Assets & Impact
List critical assets and what happens if compromised:
- User data (PII, passwords, tokens)
- Business logic (pricing, transactions)
- Infrastructure (API keys, cloud credentials)
- Availability (critical endpoints)

### 5. Attack Surface Map
Identify the TOP 5-10 most attackable surfaces with specific code locations:
- format: "description → file:line → attack vector"

### 6. Risk Heatmap
Rate each attack surface: CRITICAL / HIGH / MEDIUM / LOW with brief justification.

---

## Output format (JSON only):

{
  "project_name": "string",
  "project_type": "web_app|api|cli|library|mobile_backend|other",
  "summary": "1-2 sentence executive summary of security posture",
  "stack": {
    "language": "python|javascript|go|...",
    "framework": "django|flask|express|...",
    "database": "postgresql|mongodb|...",
    "auth": "jwt|oauth|session|none|...",
    "external_services": ["service1", "service2"]
  },
  "entry_points": [
    {"path": "/api/users", "method": "POST", "auth_required": true, "file": "routes/users.py:42"}
  ],
  "trust_boundaries": [
    {
      "boundary": "User → Web Server",
      "stride_category": "Tampering",
      "threat": "Description of specific threat",
      "risk": "CRITICAL|HIGH|MEDIUM|LOW",
      "file_hint": "path/to/file.py:line"
    }
  ],
  "critical_assets": [
    {"asset": "User passwords", "impact": "Full account takeover", "protection": "bcrypt hashing"}
  ],
  "attack_surfaces": [
    {
      "surface": "Description",
      "location": "file:line",
      "attack_vector": "How an attacker would exploit",
      "risk": "CRITICAL|HIGH|MEDIUM|LOW",
      "cwe_hint": ["CWE-89"]
    }
  ],
  "scan_priorities": [
    "Ordered list of what the deep-reducer should focus on first"
  ]
}

## Rules:
1. Be specific — reference actual files and line numbers where possible
2. Only include threats that are PLAUSIBLE for this codebase
3. If a category doesn't apply (e.g., no auth in a CLI tool), say so briefly
4. Output ONLY the JSON, no markdown, no explanation
"""

QUICK_DISCOVERY_PROMPT = """You are a security architect doing a quick codebase triage.

Given these repository files and structure, produce a MINIMAL threat model. Focus only on:
1. What the project does (1 line)
2. Top 3-5 attack surfaces (most exploitable first)
3. Stack identification

Output as JSON:
{
  "project_type": "...",
  "summary": "...",
  "top_threats": [
    {"surface": "...", "location": "file:line", "risk": "CRITICAL|HIGH|MEDIUM", "why": "..."}
  ],
  "stack": {"language": "...", "framework": "...", "auth": "..."}
}
"""


def load_api_key():
    env_path = os.path.expanduser("~/.hermes/.env")
    with open(env_path) as f:
        for line in f:
            if line.startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def collect_repo_context(repo_path: str, quick: bool = False) -> dict:
    """Gather structural info about the repo for AI analysis."""
    context = {
        "path": os.path.abspath(repo_path),
        "name": os.path.basename(os.path.abspath(repo_path)),
    }
    
    # File tree
    tree = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build'}]
        level = root.replace(repo_path, '').count(os.sep)
        indent = '  ' * level
        dir_name = os.path.basename(root) or context['name']
        tree.append(f"{indent}{dir_name}/")
        if not quick:
            for f in sorted(files)[:10]:
                tree.append(f"{indent}  {f}")
        else:
            important = [f for f in files if f.endswith(('.py', '.js', '.ts', '.go', '.rs', '.java', 'Dockerfile', 'docker-compose.yml', '.env.example', 'requirements.txt', 'package.json', 'Cargo.toml', 'go.mod'))]
            for f in sorted(important)[:5]:
                tree.append(f"{indent}  {f}")
    
    context['tree'] = '\n'.join(tree[:200])  # Cap at 200 lines
    
    # Config files
    config_files = {}
    for pattern in ['requirements.txt', 'package.json', 'Cargo.toml', 'go.mod', 
                    'Dockerfile', 'docker-compose.yml', '.env.example', 'Makefile',
                    'setup.py', 'setup.cfg', 'pyproject.toml']:
        fp = os.path.join(repo_path, pattern)
        if os.path.exists(fp):
            with open(fp, errors='ignore') as f:
                config_files[pattern] = f.read()[:1500]
    
    context['configs'] = config_files
    
    # Auth-related files
    auth_hints = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            if any(kw in f.lower() for kw in ['auth', 'login', 'session', 'jwt', 'oauth', 'token']):
                fp = os.path.join(root, f)
                if os.path.getsize(fp) < 50000:
                    with open(fp, errors='ignore') as fh:
                        content = fh.read()
                        auth_hints.append({
                            'file': os.path.relpath(fp, repo_path),
                            'snippet': content[:500]
                        })
    context['auth_files'] = auth_hints[:5]
    
    # Route/entrypoint discovery
    routes = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            fp = os.path.join(root, f)
            if os.path.getsize(fp) < 100000:
                with open(fp, errors='ignore') as fh:
                    content = fh.read()
                # Find route definitions
                route_matches = re.findall(
                    r'(?:@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\'])|'
                    r'(?:app\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\'])',
                    content
                )
                for m in route_matches:
                    path = m[0] or m[1]
                    if path:
                        routes.append({
                            'path': path,
                            'file': os.path.relpath(fp, repo_path)
                        })
    
    context['routes'] = routes[:30]
    context['route_count'] = len(routes)
    
    return context


# ── DREAD (детерминированный risk-скоринг 0-50, оси по 0-10) ──

DREAD_AXES = ("Damage", "Reproducibility", "Exploitability", "Affected Users", "Discoverability")
_RISK_DAMAGE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
_EXPLOIT_SCORE = {
    "sql": 9, "rce": 9, "command": 9, "injection": 8, "ssti": 9, "deserial": 9,
    "upload": 8, "idor": 8, "auth": 9, "ssrf": 8, "xss": 7, "csrf": 6,
    "redirect": 5, "traversal": 8, "info": 4, "disclos": 4, "log": 4, "dos": 6,
}


def dread_score(threat: dict) -> dict:
    """Детерминированный DREAD-скоринг угрозы/attack-surface.

    Не требует LLM: эвристики по risk + cwe_hint + surface-тексту.
    """
    risk = threat.get("risk", "MEDIUM")
    surface = " ".join([
        str(threat.get("surface", "")), str(threat.get("threat", "")),
        str(threat.get("attack_vector", "")), " ".join(threat.get("cwe_hint", [])),
    ]).lower()

    damage = _RISK_DAMAGE.get(risk, 4)
    reproducible = 7 if any(t in surface for t in
                            ("sql", "injection", "rce", "traversal", "ssti", "deserial")) else 5
    exploitability = 5
    for term, score in _EXPLOIT_SCORE.items():
        if term in surface:
            exploitability = max(exploitability, score)
    affected = 10 if any(t in surface for t in
                         ("auth", "idor", "privilege", "account", "bypass")) else 6
    if any(t in surface for t in ("info", "disclos", "log")):
        affected = min(affected, 7)
    discoverability = 8  # публичные классы уязвимостей

    total = damage + reproducible + exploitability + affected + discoverability
    level = ("CRITICAL" if total >= 40 else "HIGH" if total >= 30
             else "MEDIUM" if total >= 20 else "LOW")
    return {"damage": damage, "reproducibility": reproducible,
            "exploitability": exploitability, "affected_users": affected,
            "discoverability": discoverability, "total": total, "level": level}


def apply_dread(model: dict) -> dict:
    """Обогащает все threat-списки модели DREAD-скорингом (in-place)."""
    for key in ("attack_surfaces", "trust_boundaries", "top_threats"):
        for t in model.get(key, []):
            if isinstance(t, dict):
                t["dread"] = dread_score(t)
    return model


# ── PASTA (Process for Attack Simulation & Threat Analysis) — 7 стадий ──

PASTA_STAGES = [
    ("1. Define objectives", "бизнес/security-цели и что защищаем"),
    ("2. Define technical scope", "компоненты, зависимости, trust boundaries"),
    ("3. Application decomposition", "entry points, активы, потоки данных"),
    ("4. Threat analysis", "STRIDE-угрозы по каждой границе"),
    ("5. Vulnerability analysis", "угрозы → уязвимости (CWE)"),
    ("6. Attack modeling", "attack trees / векторы → PoC"),
    ("7. Risk & impact analysis", "DREAD-скоринг + приоритизация"),
]


def pasta_stages(context: dict, model: dict) -> list[dict]:
    """Сопоставляет 7 стадий PASTA с собранным контекстом (детерминированный skeleton)."""
    evidence = {
        0: model.get("summary", ""),
        1: f"stack={model.get('stack', {}).get('framework', '?')} / deps={list(context.get('configs', {}).keys())}",
        2: f"{context.get('route_count', 0)} routes, {len(context.get('auth_files', []))} auth files",
        3: f"{len(model.get('trust_boundaries', []))} trust boundaries",
        4: f"{len(model.get('attack_surfaces', model.get('top_threats', [])))} surfaces (CWE-подсказки)",
        5: "PoC → gsc_poc_deterministic / gsc_proofoffix",
        6: "DREAD-скоринг (apply_dread)",
    }
    return [{"stage": s, "purpose": p, "evidence": evidence.get(i, "")}
            for i, (s, p) in enumerate(PASTA_STAGES)]


def call_llm(prompt: str, api_key: str, model: str = "deepseek-chat") -> dict:
    """Send to DeepSeek, get structured JSON back."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security architect. Output ONLY valid JSON, no markdown."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 32768,
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
        with urlopen(req, timeout=180) as resp:
            response = json.loads(resp.read())
    except HTTPError as e:
        return {"error": f"API error {e.code}"}
    except Exception as e:
        return {"error": str(e)}
    
    content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
    
    # Extract JSON — try to fix truncated responses
    json_match = re.search(r'\{[\s\S]*', content)
    if not json_match:
        return {"error": "No JSON in response", "raw": content[:500]}
    
    json_str = json_match.group()
    # Try to fix truncated JSON by closing braces
    open_braces = json_str.count('{') - json_str.count('}')
    if open_braces > 0:
        json_str += '}' * open_braces
    # Fix truncated arrays
    open_brackets = json_str.count('[') - json_str.count(']')
    if open_brackets > 0:
        json_str += ']' * open_brackets
    
    try:
        return json.loads(json_str, strict=False)
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse failed: {e}", "raw": content[:500]}


def build_discovery_prompt(context: dict) -> str:
    """Build prompt for quick discovery mode."""
    prompt = f"""Repository: {context['name']}
Path: {context['path']}

## File Structure
{context['tree']}

## Configuration Files
"""
    for name, content in context.get('configs', {}).items():
        prompt += f"\n### {name}\n```\n{content[:500]}\n```\n"
    
    prompt += f"\n## Routes Found ({context.get('route_count', 0)})"
    for r in context.get('routes', [])[:8]:
        prompt += f"\n  {r['path']} → {r['file']}"
    
    prompt += "\n\n" + QUICK_DISCOVERY_PROMPT
    return prompt


def build_full_prompt(context: dict) -> str:
    """Build comprehensive threat modeling prompt."""
    prompt = f"""Repository: {context['name']}
Path: {context['path']}

## File Structure (abbreviated)
{context['tree']}

## Configuration Files
"""
    for name, content in context.get('configs', {}).items():
        prompt += f"\n### {name}\n```\n{content[:800]}\n```\n"
    
    prompt += f"\n## Routes/Endpoints ({context.get('route_count', 0)} total)"
    for r in context.get('routes', [])[:20]:
        prompt += f"\n  {r['path']} → {r['file']}"
    
    prompt += "\n## Auth-Related Files"
    for af in context.get('auth_files', [])[:3]:
        prompt += f"\n### {af['file']}\n```\n{af['snippet'][:300]}\n```"
    
    prompt += "\n\n" + THREAT_MODEL_PROMPT
    return prompt


def save_threat_model(model: dict, repo_path: str, output_dir: str = None):
    """Save threat model to file."""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(repo_path), '.gsc')
    os.makedirs(output_dir, exist_ok=True)
    
    model['generated_at'] = datetime.now().isoformat()
    model['repo_path'] = os.path.abspath(repo_path)
    
    path = os.path.join(output_dir, 'threat_model.json')
    with open(path, 'w') as f:
        json.dump(model, f, indent=2, ensure_ascii=False)
    
    # Also save as markdown summary
    md_path = os.path.join(output_dir, 'threat_model.md')
    with open(md_path, 'w') as f:
        f.write(f"# Threat Model: {model.get('project_name', 'Unknown')}\n\n")
        f.write(f"**Type:** {model.get('project_type', '?')}\n")
        f.write(f"**Generated:** {model['generated_at']}\n\n")
        
        if 'summary' in model:
            f.write(f"## Summary\n{model['summary']}\n\n")
        
        if 'stack' in model:
            s = model['stack']
            f.write(f"## Stack\n")
            for k, v in s.items():
                f.write(f"- **{k}:** {v}\n")
            f.write("\n")
        
        if 'attack_surfaces' in model:
            f.write(f"## Attack Surfaces\n")
            for a in model['attack_surfaces'][:10]:
                risk_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(a.get('risk', ''), '⚪')
                f.write(f"\n### {risk_icon} {a.get('surface', '?')}\n")
                f.write(f"- **Location:** {a.get('location', '?')}\n")
                f.write(f"- **Vector:** {a.get('attack_vector', '?')}\n")
                if a.get('cwe_hint'):
                    f.write(f"- **CWE:** {', '.join(a['cwe_hint'])}\n")
            f.write("\n")
        
        if 'scan_priorities' in model:
            f.write("## Scan Priorities\n")
            for i, p in enumerate(model.get('scan_priorities', []), 1):
                f.write(f"{i}. {p}\n")
    
    return path, md_path


def main():
    parser = argparse.ArgumentParser(description="GSC Threat Modeler")
    parser.add_argument("repo", help="Path to repository")
    parser.add_argument("--quick", action="store_true", help="Quick mode — minimal analysis")
    parser.add_argument("--model", default="deepseek-chat", help="LLM model")
    parser.add_argument("--output", "-o", help="Output directory for threat model")
    args = parser.parse_args()
    
    api_key = load_api_key()
    if not api_key:
        print("❌ DEEPSEEK_API_KEY not found")
        sys.exit(1)
    
    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"❌ Not a directory: {repo_path}")
        sys.exit(1)
    
    print(f"🔍 Analyzing: {os.path.basename(repo_path)}")
    print(f"   Mode: {'⚡ quick' if args.quick else '🔬 full'}")
    
    # Phase 1: Collect context
    print("   📂 Collecting codebase context...")
    context = collect_repo_context(repo_path, quick=args.quick)
    print(f"      {len(context.get('routes', []))} routes, {len(context.get('auth_files', []))} auth files, {len(context.get('configs', {}))} configs")
    
    # Phase 2: LLM analysis
    print("   🧠 AI threat modeling...")
    prompt = build_discovery_prompt(context) if args.quick else build_full_prompt(context)
    result = call_llm(prompt, api_key, args.model)
    
    if "error" in result:
        print(f"   ❌ {result['error']}")
        if "raw" in result:
            print(f"   Raw: {result['raw'][:300]}")
        sys.exit(1)
    
    # Phase 3: Save
    apply_dread(result)
    result.setdefault("pasta_stages", pasta_stages(context, result))
    json_path, md_path = save_threat_model(result, repo_path, args.output)
    print(f"\n✅ Threat model saved:")
    print(f"   📄 {json_path}")
    print(f"   📝 {md_path}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"🎯 {result.get('project_name', os.path.basename(repo_path))}")
    print(f"   Type: {result.get('project_type', '?')}")
    if 'summary' in result:
        print(f"   {result['summary'][:120]}")
    
    attack_surfaces = result.get('attack_surfaces', result.get('top_threats', []))
    if attack_surfaces:
        print(f"\n⚔️  Top Attack Surfaces:")
        for a in attack_surfaces[:5]:
            risk = a.get('risk', '?')
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(risk, '⚪')
            print(f"   {icon} [{risk}] {a.get('surface', a.get('threat', '?'))[:80]}")
            if a.get('location'):
                print(f"      📁 {a['location']}")
    
    priorities = result.get('scan_priorities', [])
    if priorities:
        print(f"\n📋 Scan Priorities for deep-reducer:")
        for i, p in enumerate(priorities[:5], 1):
            print(f"   {i}. {p[:100]}")


if __name__ == "__main__":
    main()
