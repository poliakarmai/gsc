# Recon Contract — единый слой рекогносцировки GSC

> Контракт для всех модулей рекон-фронта GSC (bug bounty / external attack
> surface). Читают кодинг-агент (Макс) и судья перед приёмкой.
> Расхождения с эталоном = FAIL.

## 0. Зачем этот слой

До сих пор модули GSC лежали плоско в `gsc_cli/`. Recon — новый домен, и он
сразу оформляется как **пакет `gsc_recon/`** с единым контрактом, чтобы не
плодить четвёртую плоскую свалку. Каждый модуль — реализация одной
абстракции, а не разрозненный скрипт.

## 1. Инварианты (жёсткие)

1. **stdlib-only** — `urllib.request`, `urllib.parse`, `json`, `re`, `socket`,
   `ssl`, `dataclasses`, `typing`. НЕ `requests`, НЕ `dnspython`, НЕ `scapy`.
2. **English-only** в коде/комментариях/assert. Исключение — копирайт
   «Алексей Поляков» в SPDX-заголовке (строки 1–3).
3. **Нет `os.environ` на уровне модуля**, нет хардкод-секретов/токенов.
4. **Толерантность к сети**: любая ошибка сети/парсинга/таймаута → пустой
   результат (`[]` / `{}` / dataclass c `valid=False`), **никогда** не бросать
   исключение наружу.
5. **Разделение слоёв**: сеть — только в `fetch()`. `parse_*` / `normalize_*` /
   `detect_*` — чистые функции без I/O (unit-testable без сети).
6. **Пассивность**: по умолчанию passive-recon (публичные источники: crt.sh,
   DNS-резолв). Активное сканирование (port scan, brute) — отдельный флаг,
   никогда не по умолчанию.

## 2. Контракт модуля (паттерн fetch → parse → normalize)

```python
# каждый модуль в gsc_recon/<name>.py предоставляет:

class <Name>Client:                       # сетевой слой
    def __init__(self, timeout: int = 30): ...
    def fetch(self, target: str):         # сеть → сырой результат, tolerant

def parse_<name>(payload: object, ...) -> list | dict:   # чистая, tolerant
def normalize_<name>(items: list, ...) -> list:          # чистая: lower, strip,
                                                         # dedup, sort, filter
def detect_<name>(...) -> list[<Name>Match]:             # чистая (для tech)

@dataclass
class <Name>Result:                       # result dataclass + to_dict()
    ...
    def to_dict(self) -> dict: ...
```

## 3. Реестр модулей (4)

| Модуль | Назначение | Источник | Паттерн |
|---|---|---|---|
| `gsc_recon/subdomain_enum.py` | перечисление субдоменов | crt.sh CT-logs | fetch→parse→normalize→filter_live |
| `gsc_recon/tech_detect.py` | определение тех-стека | HTTP-заголовки + HTML | detect (чистая, вход скачан) |
| `gsc_recon/dns_enum.py` | DNS-записи A/CNAME/MX/TXT/NS | резолвер | fetch→parse→normalize |
| `gsc_recon/http_probe.py` | HTTP-пробы статус/заголовки | GET/HEAD по хостам | fetch→parse→normalize |

## 4. Единая точка входа

`gsc.py recon --domain example.com` собирает все модули в один отчёт:

```
subdomains → [dns resolve] → [http probe] → [tech detect] → ReconReport
```

Пайплайн держит один orchestrator (`gsc_recon/orchestrator.py`), модули друг
друга не импортируют — обмен через примитивы (list[str] доменов, dict заголовков).

## 5. Правила судьи (adversarial review)

1. Reviewer получает **только код + этот контракт** — без reasoning автора.
2. Установка: **«предположи, что код неверен — найди, как он ломается»**.
3. Проверять на **реальных edge-case входах** (битый JSON, timeout, None,
   не-string, wildcard-домены, IDN/юникод-домены).
4. «Если нужен абзац-комментарий для оправдания workaround — код неверен.»
5. Вердикт: `PASS` / `FAIL` + дефекты `file:line` + неблокирующие замечания.
