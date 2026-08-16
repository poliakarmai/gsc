"""Attack-path graph: Mermaid-визуализация цепочек из ChainComposer.

ChainComposer (gsc_chain_composer.py) уже строит attack chains через LLM
(composed_severity > max individual severity, dedupe). Чего нет — визуализации:
chains лежат в scan.json как JSON/текст, для PR/README/CI нужен граф. Модуль
НЕ дублирует логику композиции — берёт готовый report["chains"] и рендерит
Mermaid flowchart (LR).

CLI: gsc.py attack-graph --scan scan.json --out attack_paths.md
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping

_SEV_COLOR = {
    "CRITICAL": "#ff4d4f",
    "HIGH": "#ff7a45",
    "MEDIUM": "#faad14",
    "LOW": "#52c41a",
}


def _clean(label: str, limit: int = 60) -> str:
    return label.replace('"', "'").replace("\n", " ").strip()[:limit]


def chains_to_mermaid(chains: Iterable[Mapping], title: str = "Attack Paths") -> str:
    """Mermaid flowchart (LR) из report["chains"] (list[dict]).

    Узлы — finding_keys (гарантированное поле), ребро — composed_severity.
    narrative идёт конечной подписью цепочки. Без нового LLM-вызова.
    """
    out = ["flowchart LR", f'    start["{_clean(title)}"]']
    for ci, ch in enumerate(chains):
        sev = str(ch.get("composed_severity", "UNKNOWN")).upper()
        keys = ch.get("finding_keys") or []
        prev = "start"
        for ki, key in enumerate(keys):
            nid = f"n{ci}_{ki}"
            out.append(f'    {nid}["{_clean(str(key))}"]:::{sev.lower()}')
            out.append(f"    {prev} -->|{sev}| {nid}")
            prev = nid
        narr = ch.get("narrative") or ""
        if narr:
            out.append(f'    {prev} -.->|"{_clean(narr)}"| end{ci}["⚙"]')
    for sev in _SEV_COLOR:
        out.append(f"    classDef {sev.lower()} fill:{_SEV_COLOR[sev]},stroke:#333,color:#fff")
    return "\n".join(out)


def render_attack_graph(scan_path: str, out_path: str, title: str = "Attack Paths") -> str:
    """scan.json (с полем chains) → .md с mermaid-блоком. Возвращает путь."""
    data = json.loads(Path(scan_path).read_text())
    chains = data.get("chains") or data.get("attack_chains") or []
    md = f"# {title}\n\n```mermaid\n{chains_to_mermaid(chains, title)}\n```\n"
    Path(out_path).write_text(md)
    return out_path
