# GSC Rule Registry — own YAML rule registry

Declarative pattern DSL: rules are written in YAML and compiled into GSC detectors
without writing Python code (`gsc_core/gsc_yaml_rules.py`).

## File convention

- **One file = one rule** (or a group of related rules under a single `rules:`).
- File name = `<id>.yml` (e.g. `no-unsafe-deserialization.yml`).
- Rule identifier (`id`) — kebab-case, unique within the registry.

## Rule metadata

```yaml
rules:
  - id: no-unsafe-deserialization      # required, kebab-case
    severity: CRITICAL                  # CRITICAL|HIGH|MEDIUM|LOW (or ERROR/WARNING/INFO)
    confidence: 0.85                    # 0.0–1.0
    languages: [python]                 # python|javascript|go|java|ruby|...
    message: "Unsafe deserialization ..."  # required — what and why
    patterns:                           # required — at least one
      - regex: "pickle\\.loads\\("     # raw regex (GSC-style)
        title: "pickle.loads() — unsafe deserialization"
      # or a declarative pattern:
      # - pattern: "pickle.loads($X)"   # → compiled to regex
    not-patterns:                       # negation guards (optional)
      - regex: "yaml\\.safe_load"
    fix: "Use yaml.safe_load() or an allowlist"   # optional
    references:                         # optional
      - "https://cwe.mitre.org/data/definitions/502.html"
```

## Pattern formats

| Key | Semantics |
|------|-----------|
| `pattern: "eval($X)"` | declarative — `$X`→metavariable, `...`→ellipsis, compiled to regex |
| `pattern-regex: "..."` | raw regex, as-is |
| `patterns: [{regex: ..., title: ...}]` | GSC-style: list of regex + title |
| `pattern-either: [...]` | OR of alternatives |
| `not-patterns` / `not` / `pattern-not` | negation guards — a match suppresses the finding |

## Commands

```bash
gsc registry list                    # compiled + source YAML rules
gsc registry add <file.yml>          # compile and register (merge-safe)
gsc registry update <path|git-url>   # import community rules
```

Compiled detectors land in `gsc_core/gsc_detectors/yaml_rules/` and are
automatically connected to the registry (`get_detectors()`) with `rule_id = YAML-<hash>`.

## Priority vs built-in detectors

Built-in detectors (`GS001`–`GS0xx`) take priority: do not write a YAML rule if the
vulnerability is already covered by a built-in detector (that would produce duplicate
findings). YAML rules are for **new** patterns not covered by the 49 detectors.
