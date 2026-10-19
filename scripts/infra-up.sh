#!/usr/bin/env bash
# 启动 IAM 自有隔离 PG17/Redis7（Apple Container），仅发布到 127.0.0.1。
# 幂等：已存在的容器直接 start；角色/授权重复执行保持一致。
# 不触碰任何共享容器、共享 PG(5432) 与共享 Redis；不读取源仓库 .env。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
test -f .env.local || { echo "缺少 .env.local（可由 .env.example 复制并填入合成随机值）"; exit 1; }
set -a; . ./.env.local; set +a
: "${IAM_PG_DB:=iam_identity}"

PG_CONTAINER=iam-pg17
REDIS_CONTAINER=iam-redis7
PG_VOLUME=iam-pg17-data
REDIS_VOLUME=iam-redis7-data
PG_IMAGE=docker.io/library/postgres:17-alpine
REDIS_IMAGE=docker.io/library/redis:7-alpine

for p in "${IAM_PG_PORT}" "${IAM_REDIS_PORT}"; do
  if nc -z 127.0.0.1 "$p" 2>/dev/null; then
    # 端口可能由本脚本旧容器占用；继续走 start 路径，若为他人进程后续健康检查会失败
    echo "提示：127.0.0.1:$p 已在监听"
  fi
done

container volume create "$PG_VOLUME" >/dev/null 2>&1 || true
container volume create "$REDIS_VOLUME" >/dev/null 2>&1 || true

ensure_container() {
  local name="$1"; shift
  if container list 2>/dev/null | grep -q "^$name[[:space:]]"; then
    echo "$name 已在运行"
  elif container inspect "$name" >/dev/null 2>&1; then
    container start "$name" >/dev/null
    echo "$name 已启动（既有容器）"
  else
    container run -d --name "$name" "$@" >/dev/null
    echo "$name 已创建并启动"
  fi
}

ensure_container "$PG_CONTAINER" \
  -p "127.0.0.1:${IAM_PG_PORT}:5432" \
  --mount "type=volume,source=${PG_VOLUME},target=/var/lib/postgresql" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD="${IAM_PG_MIGRATE_PASSWORD}" \
  -e POSTGRES_DB="${IAM_PG_DB}" \
  "$PG_IMAGE"

ensure_container "$REDIS_CONTAINER" \
  -p "127.0.0.1:${IAM_REDIS_PORT}:6379" \
  --mount "type=volume,source=${REDIS_VOLUME},target=/data" \
  "$REDIS_IMAGE" \
  redis-server --appendonly yes --save 60 1 --requirepass "${IAM_REDIS_PASSWORD}"

echo "等待 PG 就绪..."
for i in $(seq 1 60); do
  if container exec "$PG_CONTAINER" pg_isready -U postgres -d "$IAM_PG_DB" >/dev/null 2>&1; then break; fi
  sleep 1
done
container exec "$PG_CONTAINER" pg_isready -U postgres -d "$IAM_PG_DB"

SQL_FILE="$(mktemp /tmp/iam-provision.XXXXXX)"
chmod 600 "$SQL_FILE"
cleanup() { rm -f "$SQL_FILE"; }
trap cleanup EXIT
cat > "$SQL_FILE" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${IAM_PG_MIGRATE_USER}') THEN
    EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
      '${IAM_PG_MIGRATE_USER}', '${IAM_PG_MIGRATE_PASSWORD}');
  ELSE
    EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
      '${IAM_PG_MIGRATE_USER}', '${IAM_PG_MIGRATE_PASSWORD}');
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${IAM_PG_APP_USER}') THEN
    EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
      '${IAM_PG_APP_USER}', '${IAM_PG_APP_PASSWORD}');
  ELSE
    EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
      '${IAM_PG_APP_USER}', '${IAM_PG_APP_PASSWORD}');
  END IF;
END
\$\$;
GRANT CONNECT, CREATE ON DATABASE ${IAM_PG_DB} TO ${IAM_PG_MIGRATE_USER};
GRANT CONNECT ON DATABASE ${IAM_PG_DB} TO ${IAM_PG_APP_USER};
REVOKE ALL ON SCHEMA public FROM PUBLIC;
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='iam') THEN
    CREATE SCHEMA iam AUTHORIZATION ${IAM_PG_MIGRATE_USER};
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='iam_auth') THEN
    CREATE SCHEMA iam_auth AUTHORIZATION ${IAM_PG_MIGRATE_USER};
  END IF;
END
\$\$;
GRANT USAGE ON SCHEMA iam, iam_auth TO ${IAM_PG_APP_USER};
GRANT CREATE ON SCHEMA iam, iam_auth TO ${IAM_PG_MIGRATE_USER};
ALTER SCHEMA iam OWNER TO ${IAM_PG_MIGRATE_USER};
ALTER SCHEMA iam_auth OWNER TO ${IAM_PG_MIGRATE_USER};
SQL
container exec -i "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$IAM_PG_DB" < "$SQL_FILE"

# 迁移属主的默认权限：未来新建表/序列/函数自动向请求角色授最小 DML
cat > "$SQL_FILE" <<SQL
ALTER DEFAULT PRIVILEGES FOR ROLE ${IAM_PG_MIGRATE_USER} IN SCHEMA iam
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${IAM_PG_APP_USER};
ALTER DEFAULT PRIVILEGES FOR ROLE ${IAM_PG_MIGRATE_USER} IN SCHEMA iam
  GRANT USAGE, SELECT ON SEQUENCES TO ${IAM_PG_APP_USER};
ALTER DEFAULT PRIVILEGES FOR ROLE ${IAM_PG_MIGRATE_USER} IN SCHEMA iam, iam_auth
  GRANT EXECUTE ON FUNCTIONS TO ${IAM_PG_APP_USER};
SQL
PGPASSWORD="${IAM_PG_MIGRATE_PASSWORD}" container exec -i -e PGPASSWORD "$PG_CONTAINER" \
  psql -v ON_ERROR_STOP=1 -U "${IAM_PG_MIGRATE_USER}" -d "$IAM_PG_DB" -h 127.0.0.1 < "$SQL_FILE"

echo "等待 Redis 就绪..."
for i in $(seq 1 30); do
  if container exec "$REDIS_CONTAINER" redis-cli -a "${IAM_REDIS_PASSWORD}" --no-auth-warning ping 2>/dev/null | grep -q PONG; then break; fi
  sleep 1
done
container exec "$REDIS_CONTAINER" redis-cli -a "${IAM_REDIS_PASSWORD}" --no-auth-warning ping

echo
echo "基础设施就绪（仅回环）："
echo "  PG    jdbc:postgresql://127.0.0.1:${IAM_PG_PORT}/${IAM_PG_DB}"
echo "  Redis 127.0.0.1:${IAM_REDIS_PORT}"
