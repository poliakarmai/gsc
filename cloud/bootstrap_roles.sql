-- Роль приложения БЕЗ superuser — иначе RLS молча не применяется.
-- Пароль инжектится из env контейнера GSC_APP_PASSWORD через psql \set
-- (backtick-shell). Fail-closed (GSC-007): дефолтного секрета в репо нет —
-- если GSC_APP_PASSWORD не задан, роль создаётся БЕЗ пароля (логин запрещён),
-- а не с предсказуемым dev_app_pw.
\set gsc_pw `echo "${GSC_APP_PASSWORD:-}"`

DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gsc_app') THEN
      CREATE ROLE gsc_app LOGIN PASSWORD :'gsc_pw';
   ELSE
      ALTER ROLE gsc_app PASSWORD :'gsc_pw';
   END IF;
END $$;

GRANT USAGE ON SCHEMA public TO gsc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gsc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gsc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gsc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO gsc_app;

-- Принудительный RLS даже для владельца таблиц
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE verdicts FORCE ROW LEVEL SECURITY;
ALTER TABLE scans    FORCE ROW LEVEL SECURITY;