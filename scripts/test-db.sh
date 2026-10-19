#!/usr/bin/env bash
# 仅按需创建空 iam_test；表由 server 的 it profile / Flyway 迁移创建。
set +x
set -euo pipefail
if [[ $# -ne 1 || ( "${1:-}" != create && "${1:-}" != drop ) ]]; then
  echo "用法：bash scripts/test-db.sh create|drop（仅 iam_test，不接受库名）" >&2
  exit 2
fi
readonly action="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$ROOT/.env.local" ]] || { echo "缺少本机 .env.local" >&2; exit 2; }
. "$ROOT/.env.local"
if [[ "${IAM_PG_MIGRATE_USER:-}" != iam_migrate || "${IAM_PG_APP_USER:-}" != iam_app ]]; then
  echo ".env.local 必须配置 IAM_PG_MIGRATE_USER=iam_migrate、IAM_PG_APP_USER=iam_app" >&2
  exit 2
fi

# 使用既有容器本地 postgres 管理连接；不创建角色、不改口令、不读取 IAM_PG_DB。
if [[ "$action" == create ]]; then
  container exec -i iam-pg17 psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_migrate')
     OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_app') THEN
    RAISE EXCEPTION '缺少既有 iam_migrate/iam_app 角色';
  END IF;
END $$;
-- 已存在则失败，绝不覆盖或复用可能含数据的库。
CREATE DATABASE iam_test OWNER iam_migrate;
REVOKE ALL ON DATABASE iam_test FROM PUBLIC;
GRANT CONNECT ON DATABASE iam_test TO iam_app;
SQL
  container exec -i iam-pg17 psql -X -v ON_ERROR_STOP=1 -U postgres -d iam_test <<'SQL'
BEGIN;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA iam AUTHORIZATION iam_migrate;
CREATE SCHEMA iam_auth AUTHORIZATION iam_migrate;
GRANT USAGE ON SCHEMA iam, iam_auth TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam
  GRANT USAGE, SELECT ON SEQUENCES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam, iam_auth
  GRANT EXECUTE ON FUNCTIONS TO iam_app;
COMMIT;
SQL
else
  container exec -i iam-pg17 psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_stat_activity WHERE datname = 'iam_test') THEN
    RAISE EXCEPTION 'iam_test 有活跃连接，拒绝删除；请先结束测试连接';
  END IF;
END $$;
-- 不使用 FORCE、不终止会话；检查后若出现新连接，PostgreSQL 仍会拒绝删除。
DROP DATABASE iam_test;
SQL
fi
