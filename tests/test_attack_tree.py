"""GSC Attack Tree tests (deterministic goal decomposition).

Contract:
- build_attack_tree() is deterministic: no LLM, same input → same tree;
- empty surface list never crashes (single "no attack surface" leaf);
- surfaces group into category sub-goals (OR nodes);
- complementary category pairs produce AND nodes;
- tree_risk() aggregates severity correctly;
- tree_to_mermaid() emits valid Mermaid flowchart syntax.
"""
from gsc_attack_tree import (
    build_attack_tree, categorize_surface, tree_to_mermaid, tree_risk,
    render_attack_tree,
)


def _surfaces():
    return [
        {"surface": "SQL injection in login", "risk": "CRITICAL",
         "attack_vector": "unsanitized query", "cwe_hint": ["CWE-89"],
         "location": "app.py:42"},
        {"surface": "Verbose error leaks stack", "risk": "LOW",
         "attack_vector": "debug endpoint", "cwe_hint": ["CWE-200"],
         "location": "app.py:10"},
        {"surface": "Missing authz on admin route", "risk": "HIGH",
         "attack_vector": "IDOR", "cwe_hint": ["CWE-862"],
         "location": "routes/admin.py:7"},
    ]


def test_categorize_surface_by_cwe():
    assert categorize_surface({"cwe_hint": ["CWE-89"], "surface": ""}) == "injection"
    assert categorize_surface({"cwe_hint": ["CWE-200"], "surface": ""}) == "exposure"
    assert categorize_surface({"cwe_hint": ["CWE-862"], "surface": ""}) == "authz"


def test_categorize_surface_by_keyword():
    assert categorize_surface({"cwe_hint": [], "surface": "SQL injection"}) == "injection"
    assert categorize_surface({"cwe_hint": [], "surface": "stored XSS"}) == "xss"
    assert categorize_surface({"cwe_hint": [], "surface": "random text"}) == "other"


def test_build_attack_tree_is_deterministic():
    s = _surfaces()
    t1 = build_attack_tree(s)
    t2 = build_attack_tree(s)
    assert t1.to_dict() == t2.to_dict()


def test_build_attack_tree_empty_never_crashes():
    tree = build_attack_tree([])
    assert tree.operator == "OR"
    assert len(tree.children) == 1
    assert tree.children[0].operator == "LEAF"


def test_build_attack_tree_groups_categories():
    tree = build_attack_tree(_surfaces())
    # injection, exposure, authz → at least 3 category nodes
    cat_goals = [c.goal for c in tree.children if c.operator == "OR"]
    assert any("injection" in g for g in cat_goals)
    assert any("exposure" in g for g in cat_goals)
    assert any("authz" in g for g in cat_goals)
    # leaves are attached under category nodes
    leaves = [c for c in tree.children if c.operator == "OR" and c.children]
    assert leaves, "expected category sub-goals with leaves"


def test_build_attack_tree_has_and_node():
    # exposure + authz coexist → AND node must be produced
    tree = build_attack_tree(_surfaces())
    and_nodes = [c for c in tree.children if c.operator == "AND"]
    assert and_nodes, "complementary categories should form an AND node"


def test_tree_risk_aggregates():
    tree = build_attack_tree(_surfaces())
    assert tree_risk(tree) == "CRITICAL"  # SQL injection present


def test_tree_to_mermaid_syntax():
    tree = build_attack_tree(_surfaces())
    md = tree_to_mermaid(tree)
    assert md.startswith("flowchart TD")
    assert "root[" in md or '["' in md
    assert "-->|OR|" in md or "-->|AND|" in md
    # severity classes are now APPLIED to nodes (not dead classDef)
    assert ":::critical" in md or ":::high" in md or ":::low" in md


def test_tree_to_mermaid_no_duplicate_nodes():
    # AND nodes share category sub-goals; memoization must emit each node ONCE.
    tree = build_attack_tree(_surfaces())
    md = tree_to_mermaid(tree)
    # "Exploit exposure weakness" appears both as an OR category and inside an
    # AND node — with memoization it must be emitted exactly once.
    assert md.count("Exploit exposure weakness") == 1
    assert md.count("Verbose error leaks stack") == 1
    assert md.count("SQL injection in login") == 1
    assert md.count("Missing authz on admin route") == 1


def test_render_attack_tree_writes_file(tmp_path):
    out = str(tmp_path / "tree.md")
    result = render_attack_tree(_surfaces(), out)
    assert result == out
    content = open(out).read()
    assert content.startswith("# ")
    assert "```mermaid" in content
