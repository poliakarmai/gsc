# POF Parser Contract — единый источник для PoF-парсеров и судьи

> Proof-of-Fix (PoF) multilingual-парсеры: контракт, которому обязан
> соответствовать каждый `gsc_cli/gsc_pof_*_parser.py`.
> Эту страницу читают **и** кодинг-агент (Макс/M3), **и** судья (leaf-ревью)
> перед приёмкой. Расхождения с эталоном = FAIL.

## 1. Инварианты (жёсткие)

1. **stdlib-only** — `re`, `json`, `xml.etree.ElementTree`, `dataclasses`, `typing`.
   НЕ `tomllib`/`tomli` (CI на Python 3.10), НЕ `yaml`/`ruamel`/`structlog`/`prometheus`.
2. **English-only** в коде, комментариях, docstring, assert-сообщениях.
   Исключение — копирайт `Алексей Поляков` в SPDX-заголовке (строки 1–3).
3. **Нет `os.environ` на уровне модуля** (только внутри функций, если нужно).
4. **Нет хардкод-секретов/токенов**.
5. **Чистые функции**: нет файлового I/O, нет сети, нет env — на вход строки/списки,
   на выход dataclass. Полностью unit-testable в изоляции.
6. **Толерантный парсинг**: пустой ввод / `None` / не-string / битый ввод →
   `valid=False`, **никогда** не бросать исключение.
7. **Backward-compat**: новый модуль — алиасы не нужны; существующие публичные
   имена не переименовывать.

## 2. Контракт сигнатур

```python
def detect_<lang>_project(files: Iterable[str]) -> bool:
    # True если в списке есть manifest-файл этого языка.
    # basename через rsplit("/", 1)[-1].rsplit("\\", 1)[-1], case-insensitive.
    # Пропускать не-string элементы. Пустой список -> False.

def parse_<manifest>(content: str) -> <Lang>Project:
    # line-based / json / xml-разбор. Толерантно (см. §1.6).
```

Dataclass-контракт:
```python
@dataclass
class <Lang>Project:
    valid: bool = False
    # ... поля экстракции ...
    def to_dict(self) -> dict: ...
    def require_for(self, name: str) -> <Lang>Package | None:  # exact match, None на промахе
```

`valid=True` только если распознан хотя бы один валидный артефакт
(зависимость/пакет с непустым именем и т.п.).

## 3. Реестр парсеров (10)

| Модуль (`gsc_cli/`) | detect | parse | Project | Manifest |
|---|---|---|---|---|
| `gsc_pof_cargo_lock_parser.py` | `detect_cargo_lock_project` | `parse_cargo_lock` | `CargoLockProject` | `Cargo.lock` |
| `gsc_pof_csproj_parser.py` | `detect_csharp_project` | `parse_csproj` | `CsprojProject` | `*.csproj` |
| `gsc_pof_go_parser.py` | `detect_go_project` | `parse_go_mod` | `GoProject` | `go.mod` |
| `gsc_pof_gradle_parser.py` | `detect_gradle_project` | `parse_gradle` | `GradleProject` | `build.gradle` |
| `gsc_pof_java_parser.py` | `detect_java_project` | `parse_pom_xml` | `MavenProject` | `pom.xml` |
| `gsc_pof_node_parser.py` | `detect_node_project` | `parse_package_json` | `NodeProject` | `package.json` |
| `gsc_pof_php_parser.py` | `detect_php_project` | `parse_composer_json` | `ComposerProject` | `composer.json` |
| `gsc_pof_rust_parser.py` | `detect_rust_project` | `parse_cargo_toml` | `RustProject` | `Cargo.toml` |
| `gsc_pof_uv_parser.py` | `detect_uv_project` | `parse_uv_lock` | `UvProject` | `uv.lock` |
| `gsc_pof_yarn_parser.py` | `detect_yarn_project` | `parse_yarn_lock` | `YarnProject` | `yarn.lock` |

## 4. Специфика форматов (кратко)

- **line-based** (cargo_lock, gradle, rust, uv, yarn): regex, `_logical_lines` для
  многострочных значений, `[[package]]`/`[section]`-секции.
- **JSON** (node, php): `json.loads` + tolerant pre-clean (BOM, `//` line comments),
  non-string → `str()`, `require`/`dependencies` → dict.
- **XML** (java, csproj): `ElementTree`, namespace-agnostic через `_local(tag)`,
  `ParseError` → `valid=False`.
- **Кавычки**: снимать обрамляющие кавычки ДО split по разделителю И с каждой
  части после split (два места) — покрывает оба формата `"a@1, b@2"` и `"a@1", b@2`.
- **Вложенные блоки** (gradle `buildscript { dependencies { ... } }`): парсить
  только top-level `dependencies`, отслеживая общую `{}`-вложенность.
- **Числовые значения** (cargo_lock `version = 3`): отдельный regex для unquoted int.

## 5. Правила судьи (adversarial review)

1. Reviewer получает **только diff/код + этот контракт** — без reasoning автора.
2. Установка: **«предположи, что код неверен — найди, как он ломается»**.
3. Проверять на **реальных edge-case входах**, не только зелёных тестах автора.
4. **«Если нужен абзац-комментарий для оправдания workaround — код неверен, чини код.»**
5. Вердикт: `PASS` / `FAIL` + дефекты `file:line` + неблокирующие замечания.
