#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
gsc_brief_generator.py — precision-бриф детектора через DeepSeek flash.

Читает код детектора + FP/TP-срез из SQLite, шлёт на flash, пишет
DETECTOR_BRIEF_<rule>.md (черновик с гипотезами, финальную правку делает pro).

Usage:
    python3 gsc_brief_generator.py GS001 \
        --detector gsc_core/gsc_detectors/gs001_hardcoded_secret.py \
        --out docs/DETECTOR_BRIEF_GS001.md
"""
import argparse
import json
import os
import sqlite3
import sys
import urllib.request
from pathlib import Path

DEFAULT_DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
DEFAULT_MODEL = "deepseek-v4-flash"
API_URL = "https://api.deepseek.com/v1/chat/completions"


def load_api_key() -> str:
    env_path = os.path.expanduser("~/.hermes/.env")
    if os.path.exists(env_path):
        for line in Path(env_path).read_text().splitlines():
            line = line.strip()
            if line.startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def _fmt(r) -> str:
    d = (r["detail"] or "").replace("\n", " ")[:90]
    return f"- `{r['title']}` @ `{r['file_path']}:{r['line_number']}` → {d}"


def fetch(db: str, rule_id: str, verdict: str, limit: int) -> list:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    if verdict == "":
        rows = conn.execute(
            "SELECT title,file_path,line_number,detail FROM findings "
            "WHERE rule_id=? AND (revalidation_verdict IS NULL OR revalidation_verdict='') LIMIT ?",
            (rule_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT title,file_path,line_number,detail FROM findings "
            "WHERE rule_id=? AND revalidation_verdict=? LIMIT ?",
            (rule_id, verdict, limit),
        ).fetchall()
    conn.close()
    return [_fmt(r) for r in rows]


def call_flash(system: str, user: str, api_key: str, model: str) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        # flash — reasoning-модель: тратит токены на reasoning_content, поэтому
        # max_tokens должен покрывать и «думание», и финальный ответ.
        "max_tokens": 12000,
        "stream": False,
    }
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    choice = data["choices"][0]
    msg = choice["message"]
    content = (msg.get("content") or "").strip()
    if not content:
        # reasoning-модель вернула пустой content — берём reasoning как fallback
        content = (msg.get("reasoning_content") or "").strip()
    usage = data.get("usage", {})
    print(
        f"[i] finish_reason={choice.get('finish_reason')} "
        f"in={usage.get('prompt_tokens')} out={usage.get('completion_tokens')}",
        file=sys.stderr,
    )
    return content


SYSTEM = (
    "Ты — senior AppSec-инженер, специалист по точности (precision) SAST-детекторов. "
    "Твоя задача — снизить false-positive, НЕ трогая true-positive. "
    "Ты работаешь с детектором GSC (Git Security Checker). "
    "Отвечай только по-русски, в формате Markdown."
)


def build_user(rule_id, detector_code, fps, tps, unvalidated) -> str:
    return f"""Проанализируй детектор **{rule_id}** и предложи точечные precision-фиксы.

## Код детектора

```python
{detector_code}
```

## False-positive примеры (помечены FP)

{chr(10).join(fps) if fps else '(нет помеченных FP)'}

## True-positive примеры (помечены TP)

{chr(10).join(tps) if tps else '(нет помеченных TP)'}

## Выборка непроверенных находок (для контекста шума)

{chr(10).join(unvalidated) if unvalidated else '(нет)'}

## Задача

1. Сгруппируй FP по root-cause (почему паттерн срабатывает ложно).
2. Для каждого root-cause предложи **точечный** фикс: новый regex, сужение
   существующего паттерна, или дополнительный фильтр (по образцу уже существующих
   `_is_placeholder` / `_luhn_valid` / `_is_symbolic_constant`).
3. Помечай каждый фикс тегом: **[flash-гипотеза]** и оценкой влияния:
   `FP-срез: высокий/средний`, `TP-риск: низкий/средний/высокий`.
4. В конце — список «что требует pro-проверки» (где flash не уверен).

## Жёсткие ограничения (не нарушать)

- НЕ менять `rule_id`, `finding_key`, `severity`/`category`.
- НЕ переписывать детектор целиком — только точечные правки паттернов/фильтров.
- Допустимое падение TPR ≤ 3% — каждый фикс обязан это учитывать.
- НЕ предлагать фиксы, которые отключают целый паттерн без замены.

Выдай готовый Markdown-бриф в формате:
# DETECTOR BRIEF — {rule_id}
## 1. Состояние
## 2. FP root-cause (по группам)
## 3. Precision-фиксы (таблица: root-cause | фикс | FP-срез | TP-риск)
## 4. Требует pro-проверки
## 5. Рекомендуемая последовательность
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rule_id")
    ap.add_argument("--detector", required=True)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--out", default=None)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--fp-limit", type=int, default=30)
    ap.add_argument("--tp-limit", type=int, default=10)
    ap.add_argument("--sample-limit", type=int, default=20)
    args = ap.parse_args()

    api_key = load_api_key()
    if not api_key:
        print("ОШИБКА: нет DEEPSEEK_API_KEY (в ~/.hermes/.env или env)", file=sys.stderr)
        sys.exit(1)

    detector_code = Path(args.detector).read_text(errors="replace")
    fps = fetch(args.db, args.rule_id, "FP", args.fp_limit)
    tps = fetch(args.db, args.rule_id, "TP", args.tp_limit)
    unvalidated = fetch(args.db, args.rule_id, "", args.sample_limit)

    print(f"[i] {args.rule_id}: FP={len(fps)}, TP={len(tps)}, sample={len(unvalidated)}")
    print(f"[i] модель={args.model}, генерация брифа...")

    user = build_user(args.rule_id, detector_code, fps, tps, unvalidated)
    brief = call_flash(SYSTEM, user, api_key, args.model)

    out = args.out or f"docs/DETECTOR_BRIEF_{args.rule_id}.md"
    Path(out).write_text(brief + "\n")
    print(f"[✓] бриф записан: {out}")


if __name__ == "__main__":
    main()
