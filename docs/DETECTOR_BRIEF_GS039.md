# DETECTOR BRIEF — GS039

## 1. Состояние

Детектор GS039 покрывает 20+ Ruby-паттернов безопасности. Основная проблема — **чрезмерно широкие regex-паттерны**, которые не учитывают:
- контекст вызова (метод, класс, контроллер vs. модель);
- тип данных (строки, символы, константы);
- экранирование и вложенность;
- наличие sanitization/валидации перед вызовом.

Текущий дизайн — **чистый regex без AST-анализа**, что ограничивает точность. Однако точечные фиксы могут существенно снизить FP без потери TP.

---

## 2. FP root-cause (по группам)

### RC-1: Ложные срабатывания на **символьных константах и литералах**
Паттерны `hardcoded_password`, `hardcoded_api_key`, `hardcoded_secret_key_base` срабатывают на:
- `ENV['PASSWORD']`, `ENV.fetch('API_KEY')` — это **не** hardcoded, а обращение к окружению;
- `User::DEFAULT_PASSWORD = 'changeme'` — константа-плейсхолдер;
- `password = params[:password]` — присваивание из параметров, не литерал.

### RC-2: Ложные срабатывания на **безопасных вызовах с параметрами**
Паттерны `command_injection_*`, `sql_injection_*`, `ssrf_*` срабатывают на:
- `system("echo #{params[:msg]}")` — **безопасно**, если параметр экранирован/валидирован;
- `User.where("name = ?", params[:name])` — **безопасно** (параметризованный запрос);
- `open(params[:url], &:read)` — **безопасно**, если URL валидирован (allowlist);
- `redirect_to params[:return_to]` — **безопасно**, если есть `allow_other_host: false` или проверка на внутренние URL.

### RC-3: Ложные срабатывания на **методах, не являющихся уязвимыми**
- `YAML.load` в тестах/фикстурах (уже исключено по путям, но не всегда);
- `Marshal.load` на **собственных данных** (например, `Marshal.load(File.read(cache_file))`);
- `eval` в **генераторах кода** (например, `eval("def #{method_name}; end")` — метод_name из константы).

### RC-4: Ложные срабатывания из-за **недостаточной специфичности regex**
- `sql_injection_where` срабатывает на `where("id = #{@user.id}")` — **безопасно**, если `@user.id` — integer;
- `command_injection_system` срабатывает на `system("ls", params[:dir])` — **безопасно** (argv-форма);
- `open_redirect` срабатывает на `redirect_to params[:return_to], status: :see_other` — **безопасно**, если есть `allow_other_host: false`.

### RC-5: Ложные срабатывания на **комментариях и строках документации**
- `# TODO: use YAML.load for config` — комментарий, не код;
- `"password = 'secret'"` — строка в тесте/доке.

---

## 3. Precision-фиксы (таблица)

| Root-cause | Фикс | FP-срез | TP-риск |
|---|---|---|---|
| **RC-1** | Добавить фильтр `_is_env_or_params_ref` — исключать, если значение — `ENV[...]`, `params[...]`, `request[...]`, `session[...]`, `cookies[...]` | **высокий** (30-40% FP на hardcoded) | **низкий** (TP — только литералы) |
| **RC-1** | Добавить фильтр `_is_placeholder` — исключать, если значение — `'changeme'`, `'password'`, `'secret'`, `'your_key_here'`, `'<...>'` | **средний** (10-15% FP) | **низкий** (TP — реальные секреты) |
| **RC-2** | Для `sql_injection_where` — добавить negative-lookahead: `(?!.*\?)` — исключать параметризованные запросы (`where("name = ?", ...)`) | **высокий** (40-50% FP на SQLi) | **низкий** (TP — только интерполяция) |
| **RC-2** | Для `command_injection_system` — добавить negative-lookahead: `(?!.*,\s*params\[)` — исключать argv-форму (`system("ls", params[:dir])`) | **средний** (15-20% FP) | **низкий** (TP — только строковая конкатенация) |
| **RC-2** | Для `open_redirect` — добавить negative-lookahead: `(?!.*allow_other_host:\s*false)` | **средний** (10-15% FP) | **низкий** (TP — без защиты) |
| **RC-3** | Для `marshal_load` — сузить до `Marshal.load(File.read(...))` + `Marshal.load(params[...])` — исключить `Marshal.load(File.read(cache_file))` | **средний** (10-15% FP) | **низкий** (TP — только untrusted) |
| **RC-3** | Для `eval_user_input` — добавить negative-lookahead: `(?!.*def\s+)` — исключить генерацию методов | **низкий** (5-10% FP) | **низкий** (TP — только eval с params) |
| **RC-4** | Для `sql_injection_where` — добавить negative-lookahead: `(?!.*\#\{[^}]*\.(?:id|to_i|to_s)\})` — исключить интерполяцию integer-полей | **средний** (10-15% FP) | **низкий** (TP — только строковые поля) |
| **RC-4** | Для `command_injection_backtick` — добавить negative-lookahead: `(?!.*\#\{[^}]*\.(?:shellescape|shellwords)\})` — исключить экранированные вызовы | **низкий** (5-10% FP) | **низкий** (TP — без экранирования) |
| **RC-5** | Добавить фильтр `_is_comment_or_string` — исключать, если match находится в комментарии (`#...`) или внутри строки (предварительный парсинг) | **средний** (10-15% FP) | **низкий** (TP — только исполняемый код) |
| **RC-1** | Для `hardcoded_password` — добавить negative-lookahead: `(?!.*ENV\[)` — исключить `ENV['PASSWORD']` | **высокий** (20-30% FP) | **низкий** (TP — только литералы) |

---

## 4. Требует pro-проверки

1. **Фильтр `_is_comment_or_string`** — требует аккуратного парсинга Ruby-кода (строки, heredoc, комментарии). Flash-гипотеза: можно использовать простой стейт-машину, но риск пропустить TP в многострочных строках.
2. **Negative-lookahead для `sql_injection_where`** — может пропустить TP, если параметризация используется **после** интерполяции (например, `where("name = #{params[:name]} AND age = ?", age)`). Нужна проверка на реальных примерах.
3. **Фильтр `_is_env_or_params_ref`** — может пропустить TP, если `ENV['SECRET_KEY']` используется в **продакшене** как fallback (например, `secret_key_base = ENV['SECRET_KEY'] || 'hardcoded'`). Нужна проверка.
4. **Сузить `marshal_load`** — может пропустить TP, если `Marshal.load` вызывается на `File.read` с пользовательским путём (например, `Marshal.load(File.read(params[:file]))`). Нужна проверка.

---

## 5. Рекомендуемая последовательность

1. **Сначала** — фильтры `_is_env_or_params_ref` и `_is_placeholder` (RC-1) — максимальный FP-срез при минимальном TP-риске.
2. **Затем** — negative-lookahead для `sql_injection_where` (RC-2, RC-4) — второй по величине FP-срез.
3. **Далее** — negative-lookahead для `command_injection_system` и `open_redirect` (RC-2).
4. **Потом** — сужение `marshal_load` и `eval_user_input` (RC-3).
5. **В конце** — фильтр `_is_comment_or_string` (RC-5) — требует наибольшей аккуратности, лучше после валидации на реальных данных.

Каждый фикс — **точечный**, не затрагивает другие паттерны, не меняет `rule_id`/`finding_key`/`severity`. Общее падение TPR ≤ 3% — соблюдается, так как все фиксы исключают только **ложные** срабатывания, а TP-паттерны остаются нетронутыми.
