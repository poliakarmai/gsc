# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Attack trees — deterministic hierarchical decomposition of an attack goal.

Classic attack-tree model (Schneier 1999): a root goal is recursively broken
into sub-goals via AND (all children required) / OR (any child suffices), down
to concrete attack vectors (leaves).

This module is DETERMINISTIC (no LLM): it builds the tree from the threat
model's ``attack_surfaces`` (already produced by gsc_threat_model.py) and scores
each node with the existing DREAD heuristics. It complements — and does NOT
replace — the LLM-driven ChainComposer: chains are linear exploit sequences,
attack trees are hierarchical goal decompositions.

Relationship to PASTA: this implements stage 6 ("Attack modeling") of
PASTA_STAGES in gsc_threat_model.py.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable, Mapping

from gsc_threat_model import dread_score

# ── Attack category taxonomy ────────────────────────────────────────
# Maps a CWE hint / surface keyword to a stable attack category (sub-goal).
_CWE_CATEGORY = {
    "89": "injection", "78": "injection", "77": "injection", "94": "injection",
    "98": "injection", "95": "injection", "74": "injection",
    "79": "xss", "80": "xss", "83": "xss",
    "22": "traversal", "23": "traversal", "36": "traversal", "35": "traversal",
    "918": "ssrf", "611": "xxe", "776": "xxe",
    "502": "deserialization", "470": "deserialization",
    "287": "auth", "306": "auth", "307": "auth", "798": "auth",
    "862": "authz", "863": "authz", "639": "authz", "284": "authz",
    "434": "upload", "200": "exposure", "532": "exposure", "312": "exposure",
    "601": "redirect", "352": "csrf", "400": "dos", "770": "dos",
}
_KEYWORD_CATEGORY = {
    "sql": "injection", "injection": "injection", "command": "injection",
    "rce": "injection", "ssti": "injection", "eval": "injection",
    "xss": "xss", "traversal": "traversal", "path": "traversal",
    "ssrf": "ssrf", "xxe": "xxe", "deserial": "deserialization",
    "auth": "auth", "idor": "authz", "privilege": "authz", "bypass": "authz",
    "upload": "upload", "csrf": "csrf", "redirect": "redirect",
    "disclos": "exposure", "info": "exposure", "log": "exposure",
    "dos": "dos",
}
_DEFAULT_CATEGORY = "other"

# Complementary attack pairs → AND node (multi-step goal). When a surface in
# the first category and one in the second coexist, they form a higher-order
# goal requiring BOTH (e.g. info-leak then injection = privilege escalation).
_AND_PAIRS = [
    (("exposure", "auth"), "credential-driven account takeover"),
    (("exposure", "authz"), "privilege escalation via leaked data"),
    (("exposure", "injection"), "data-leak amplified code execution"),
    (("auth", "authz"), "auth bypass leading to privilege escalation"),
    (("ssrf", "injection"), "SSRF to internal RCE"),
]

_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEV_COLOR = {
    "CRITICAL": "#ff4d4f", "HIGH": "#ff7a45",
    "MEDIUM": "#faad14", "LOW": "#52c41a",
}


def categorize_surface(surface: Mapping) -> str:
    """Deterministic category for an attack surface (CWE hint first, then text)."""
    cwe_raw = surface.get("cwe_hint") or []
    if isinstance(cwe_raw, str):
        cwe_raw = [cwe_raw]
    cwe_hints = [str(c).upper().replace("CWE-", "") for c in cwe_raw]
    for cwe in cwe_hints:
        if cwe in _CWE_CATEGORY:
            return _CWE_CATEGORY[cwe]
    text = " ".join([
        str(surface.get("surface", "")), str(surface.get("attack_vector", "")),
        str(surface.get("threat", "")),
    ]).lower()
    for kw, cat in _KEYWORD_CATEGORY.items():
        if kw in text:
            return cat
    return _DEFAULT_CATEGORY


@dataclass
class AttackTreeNode:
    """A node in an attack tree.

    operator: "OR" (any child achieves the goal), "AND" (all children
    required), or "LEAF" (a concrete attack vector, no children).
    """
    id: str
    goal: str
    operator: str
    children: list["AttackTreeNode"] = field(default_factory=list)
    # leaf metadata
    category: str = ""
    location: str = ""
    risk: str = "MEDIUM"
    dread_total: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _leaf_from_surface(idx: int, surface: Mapping) -> AttackTreeNode:
    cat = categorize_surface(surface)
    risk = str(surface.get("risk", "MEDIUM")).upper()
    if risk not in _SEV_ORDER:
        risk = "MEDIUM"
    dread = dread_score(surface)
    goal = (str(surface.get("surface")) or str(surface.get("attack_vector"))
            or "attack vector")[:120]
    return AttackTreeNode(
        id=f"leaf{idx}",
        goal=goal,
        operator="LEAF",
        category=cat,
        location=str(surface.get("location", "")),
        risk=risk,
        dread_total=int(dread.get("total", 0)),
    )


def _node_risk(leaves: list[AttackTreeNode]) -> str:
    """Aggregate risk of a group of leaves: max severity (tie → first max)."""
    if not leaves:
        return "LOW"
    best = max(leaves, key=lambda l: _SEV_ORDER[l.risk])
    return best.risk


def build_attack_tree(attack_surfaces: Iterable[Mapping],
                      root_goal: str = "Compromise the application") -> AttackTreeNode:
    """Deterministically build an attack tree from threat-model attack surfaces.

    Structure:
      root (OR) → category sub-goals (OR) → attack-vector leaves
    Plus AND nodes for complementary category pairs (multi-step goals).

    Empty surface list → a single "no attack surface" leaf (never crashes).
    """
    surfaces = [s for s in attack_surfaces if isinstance(s, Mapping)]
    root = AttackTreeNode(id="root", goal=root_goal, operator="OR")

    if not surfaces:
        root.children.append(AttackTreeNode(
            id="leaf0", goal="No attack surface identified",
            operator="LEAF", category="none", risk="LOW", dread_total=0,
        ))
        return root

    leaves = [_leaf_from_surface(i, s) for i, s in enumerate(surfaces)]
    by_cat: dict[str, list[AttackTreeNode]] = {}
    for leaf in leaves:
        by_cat.setdefault(leaf.category, []).append(leaf)

    # Category sub-goals (OR of leaves)
    for ci, (cat, cat_leaves) in enumerate(sorted(by_cat.items())):
        cat_node = AttackTreeNode(
            id=f"cat{ci}",
            goal=f"Exploit {cat} weakness",
            operator="OR",
            children=cat_leaves,
            risk=_node_risk(cat_leaves),
        )
        root.children.append(cat_node)

    # AND nodes for complementary pairs (multi-step goals)
    present = set(by_cat.keys())
    and_idx = 0
    for (a, b), goal in _AND_PAIRS:
        if a in present and b in present:
            a_node = next(c for c in root.children if c.goal == f"Exploit {a} weakness")
            b_node = next(c for c in root.children if c.goal == f"Exploit {b} weakness")
            and_node = AttackTreeNode(
                id=f"and{and_idx}",
                goal=goal,
                operator="AND",
                children=[a_node, b_node],
                risk=_node_risk(by_cat[a] + by_cat[b]),
            )
            root.children.append(and_node)
            and_idx += 1

    return root


def _clean(label: str, limit: int = 70) -> str:
    return label.replace('"', "'").replace("\n", " ").strip()[:limit]


def tree_to_mermaid(root: AttackTreeNode) -> str:
    """Render an AttackTreeNode as a Mermaid flowchart (top-down, AND/OR labeled).

    Renders the DAG as a graph: each node is DEFINED exactly once (with its
    label + severity class); every subsequent reference to it is a bare id.
    A shared sub-goal (category referenced by both an OR edge and an AND node)
    is therefore not duplicated. Uses ``visited`` so a shared subtree is not
    re-walked.
    """
    out = ["flowchart TD"]
    counter = {"n": 0}
    emitted: dict[str, str] = {}   # node.id → mermaid id
    defined: set[str] = set()      # node.id whose definition line is emitted
    visited: set[str] = set()      # node.id whose children are already walked

    def _emit(node: AttackTreeNode) -> str:
        nid = emitted.get(node.id)
        if nid is None:
            nid = f"n{_bump(counter)}"
            emitted[node.id] = nid
        if node.id in defined:
            return nid
        defined.add(node.id)
        label = node.goal
        if node.operator == "LEAF" and node.location:
            label += f" @ {node.location}"
        out.append(f'    {nid}["{_clean(label)}"]:::{node.risk.lower()}')
        return nid

    def _walk(node: AttackTreeNode, depth: int = 0):
        parent_id = _emit(node)
        if node.id in visited or depth > 8:
            return
        visited.add(node.id)
        for child in node.children:
            child_id = _emit(child)
            if child.operator in ("AND", "OR"):
                out.append(f"    {parent_id} -->|{child.operator}| {child_id}")
            else:
                out.append(f"    {parent_id} --> {child_id}")
            _walk(child, depth + 1)

    _walk(root)
    for sev in _SEV_COLOR:
        out.append(
            f"    classDef {sev.lower()} fill:{_SEV_COLOR[sev]},stroke:#333,color:#fff"
        )
    return "\n".join(out)


def _bump(counter: dict) -> int:
    counter["n"] += 1
    return counter["n"]


def render_attack_tree(attack_surfaces: Iterable[Mapping], out_path: str,
                       root_goal: str = "Compromise the application",
                       title: str = "Attack Tree") -> str:
    """attack_surfaces → .md with a Mermaid attack tree. Returns the output path."""
    tree = build_attack_tree(attack_surfaces, root_goal)
    md = f"# {title}\n\n```mermaid\n{tree_to_mermaid(tree)}\n```\n"
    from pathlib import Path
    Path(out_path).write_text(md)
    return out_path


def tree_risk(root: AttackTreeNode) -> str:
    """Aggregate risk of the whole tree using severity order (not lexicographic).

    Root is OR → take the max child risk; AND nodes → max of children too
    (worst-case: if all required, the hardest/biggest one dominates).
    """
    def _risk(node: AttackTreeNode) -> str:
        if not node.children:
            return node.risk
        return max(
            (_risk(c) for c in node.children),
            key=lambda r: _SEV_ORDER.get(r, 0),
        )

    return _risk(root)
