#!/usr/bin/env python3
"""GS005 decomposition — assign unique pattern_ids to all 78 patterns.

Deterministic naming: GS005-<TYPE>-<LANG>-<NN>
TYPE from title keywords, LANG from language field.
"""
import re

TYPE_MAP = {
    "f-string": "FSTR", "fstring": "FSTR",
    "format(": "FMT", "%.format": "FMT", "%-format": "FMT",
    "concat": "CONCAT", "concatenat": "CONCAT", "string concatenation": "CONCAT",
    "$where": "NOSQL", "$ne": "NOSQL", "$regex": "NOSQL", "nosql": "NOSQL",
    "MongoDB": "NOSQL", "DynamoDB": "NOSQL", "Redis": "NOSQL",
    "raw": "ORM", "orm": "ORM",
    "Django": "ORM", "SQLAlchemy": "ORM", "Sequelize": "ORM",
    "Knex": "ORM", "Laravel": "ORM", "ActiveRecord": "ORM",
    "createQuery": "ORM", "Models.objects": "ORM",
    "jdbc": "JDBC", "Statement": "JDBC", "PreparedStatement": "JDBC",
    "JPA": "JDBC", "Spring": "JDBC",
    "execute": "EXEC", "cursor": "EXEC",
    "SqlCommand": "CSHARP",
}

LANG_MAP = {
    "python": "PY", "javascript": "JS", "ruby": "RB", "php": "PHP",
    "java": "JAVA", "go": "GO", "csharp": "CS", "rust": "RS",
    "generic": "GEN",
}


def assign_ids(patterns):
    """patterns: list[(regex, title, lang, needs_ctx)] → list[(pattern_id, regex, title, lang, needs_ctx)]"""
    counters = {}
    result = []
    for regex, title, lang, needs_ctx in patterns:
        ptype = "GEN"
        for key, code in TYPE_MAP.items():
            if key.lower() in title.lower():
                ptype = code
                break
        lcode = LANG_MAP.get(lang, "X")
        key = (ptype, lcode)
        counters[key] = counters.get(key, 0) + 1
        pid = f"GS005-{ptype}-{lcode}-{counters[key]:03d}"
        result.append((pid, regex, title, lang, needs_ctx))
    return result


if __name__ == "__main__":
    from gsc_core.gsc_detectors.gs005_sql_injection import _PATTERNS as OLD_PATTERNS
    new = assign_ids(OLD_PATTERNS)
    print(f"Total patterns: {len(new)}")

    # Verify uniqueness
    pids = [p[0] for p in new]
    assert len(pids) == len(set(pids)), f"DUPLICATE! {len(pids)} != {len(set(pids))}"
    print("✅ All pattern IDs unique")

    # Print summary by type
    from collections import Counter
    types = Counter(p.split("-")[1] for p in pids)
    for t, c in sorted(types.items()):
        print(f"  {t}: {c}")

    # Print first 10
    for pid, regex, title, lang, needs in new[:10]:
        print(f"  {pid} | {lang:6} | {title[:60]}")
