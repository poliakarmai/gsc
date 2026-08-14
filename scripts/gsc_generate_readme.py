#!/usr/bin/env python3
"""GSC roadmap 7.1: сгенерировать/обновить README-секцию числами из gsc_meta SSOT.

Вставляет (или обновляет) блок между маркерами
``<!-- GSC-META-START -->`` ... ``<!-- GSC-META-END -->`` в README.md:
версия, детекторы (registry + standalone = total), schema version, модули.

Запуск:  python3 scripts/gsc_generate_readme.py
Сверка:  python3 scripts/gsc_reconcile.py   (должен дать ALL MATCH)
"""
from __future__ import annotations

import sys
from pathlib import Path

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))

from gsc_meta import get_meta  # noqa: E402

START = "<!-- GSC-META-START -->"
END = "<!-- GSC-META-END -->"


def main() -> int:
    meta = get_meta()
    block = (
        f"{START}\n"
        f"**Version:** v{meta['version']} · **Detectors:** {meta['detectors_total']} "
        f"({meta['detectors_registry']} registry + {meta['detectors_standalone']} engines) · "
        f"**Schema:** v{meta['schema']} · **Modules:** {meta['modules']}\n"
        f"{END}"
    )

    readme = GSC / "README.md"
    text = readme.read_text()

    if START in text:
        start = text.index(START)
        end = text.index(END) + len(END)
        text = text[:start] + block + text[end:]
    else:
        lines = text.split("\n")
        insert_at = 1
        for i, line in enumerate(lines):
            if line.startswith("# "):
                insert_at = i + 1
                break
        lines[insert_at:insert_at] = ["", block, ""]
        text = "\n".join(lines)

    readme.write_text(text)
    print(f"✅ README: v{meta['version']}, {meta['detectors_total']} detectors "
          f"({meta['detectors_registry']}+{meta['detectors_standalone']}), "
          f"schema v{meta['schema']}, {meta['modules']} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
