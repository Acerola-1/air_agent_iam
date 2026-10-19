#!/usr/bin/env bash
# 已退役：旧在线验收入口；原主体仅保留为历史参考。
printf '%s\n' '已退役：禁止在正式环境运行旧在线验收；现行入口和隔离测试见 README.md。' >&2
exit 2

# 7.2 C25 暖连接 introspection 性能/并发/依赖故障证据（可复跑）。
# 真实 HTTP + PG iam + Redis，回环；不接入两 Python 仓库。
# 性能采集打到专用实例 19103（同 PG、Redis 逻辑库4、关闭准入限流以测核验开销本身），
# 主实例 19100 全程不重启；依赖故障阶段停的是自有容器，trap 保证恢复。
set -euo pipefail
cd "$(dirname "$0")/.."
: "${IAM_HTTP_PORT:=19100}"
BASE="http://127.0.0.1:${IAM_HTTP_PORT}"
PBASE="http://127.0.0.1:19103"
CONTAINER_BIN=/usr/local/bin/container
OUT="docs/reviews/evidence/group7"
mkdir -p "$OUT"
OUT="$OUT/perf-introspection.txt"
: "${IAM_BOOTSTRAP_ACCOUNT:?需 source .env.local}"
: "${IAM_BOOTSTRAP_PASSWORD:?需 source .env.local}"
: "${IAM_REDIS_PASSWORD:?}"
JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
PY=tools/.venv/bin/python
[ -x "$PY" ] || PY=python3

CID="perf-intro-$((RANDOM%900000+100000))"
CSEC="perf-secret-$((RANDOM%900000+100000))-z"
sha256hex() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }
PPID_PERF=""

ensure_containers_up() {
  "$CONTAINER_BIN" start iam-redis7 >/dev/null 2>&1 || true
  "$CONTAINER_BIN" start iam-pg17 >/dev/null 2>&1 || true
}
cleanup() {
  [ -n "$PPID_PERF" ] && kill "$PPID_PERF" 2>/dev/null || true
  ensure_containers_up
  for i in $(seq 1 60); do
    curl -sf "$BASE/healthz" 2>/dev/null | grep -q '"postgres":true.*"redis":true' && break
    sleep 1
  done
  "$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL || true
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
DELETE FROM iam.internal_clients WHERE client_id='$CID';
COMMIT;
SQL
}
trap cleanup EXIT

: > "$OUT"
log() { echo "$@" | tee -a "$OUT"; }

log "=== C25 introspection 暖连接性能 $(date -u +%FT%TZ) ==="
log "采集实例 ${PBASE}（专用进程：同 PG iam、Redis 逻辑库4、IAM_RATE_LIMIT_ENABLED=false）"
log "主实例 ${BASE} 不重启。阈值参考 design.md：同机暖连接 P50≤10ms / P95≤30ms；无跨请求授权结果缓存"

log "--- 种子内部客户端（iam-admin 受众 + identity:introspect，测后删除）"
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 >>"$OUT" 2>&1 <<SQL
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
INSERT INTO iam.internal_clients(client_id,name,secret_digest,scopes,audiences)
VALUES ('$CID','$CID','$(sha256hex "$CSEC")',
        ARRAY['identity:introspect']::text[], ARRAY['iam-admin']::text[])
ON CONFLICT (client_id) DO NOTHING;
COMMIT;
SQL

log "--- 人类登录取主体令牌（响应不落证据文件）"
LOGIN=$(curl -s -X POST "$BASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
TOKEN=$($PY -c 'import json,sys;print(json.loads(sys.argv[1])["access_token"])' "$LOGIN")
[ -n "${TOKEN:-}" ] || { log "登录失败: $LOGIN"; exit 1; }
log "登录成功，令牌仅保存在脚本变量中"

log "--- 启动专用采集实例 19103"
"$CONTAINER_BIN" exec -i iam-redis7 redis-cli -a "$IAM_REDIS_PASSWORD" -n 4 FLUSHDB >/dev/null 2>&1
set -a; . ./.env.local; set +a
IAM_HTTP_PORT=19103 IAM_REDIS_DB=4 IAM_RATE_LIMIT_ENABLED=false \
  "$JAVA_HOME/bin/java" -jar server/target/iam-server.jar > /tmp/c25-perf-instance.log 2>&1 &
PPID_PERF=$!
for i in $(seq 1 60); do
  curl -sf "$PBASE/healthz" 2>/dev/null | grep -q '"status":"ok"' && break
  sleep 1
done
log "采集实例 healthz: $(curl -s "$PBASE/healthz")"

"$PY" tools/perf_introspection.py --base "$PBASE" --client-id "$CID" \
  --secret "$CSEC" --token "$TOKEN" 2>&1 | tee -a "$OUT"

log ""
log "=== 依赖故障阶段（失败关闭，不缓存放行） ==="
log "--- 停 Redis：登录路径依赖 Sa-Token 摘要，应 503"
"$CONTAINER_BIN" stop iam-redis7 >/dev/null 2>&1
sleep 2
code=$(curl -s -o /tmp/c25-redis-login.json -w '%{http_code}' --max-time 10 \
  -X POST "$PBASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
log "Redis 停用时 /v1/auth/login -> $code $(cat /tmp/c25-redis-login.json)"

"$CONTAINER_BIN" start iam-redis7 >/dev/null 2>&1
for i in $(seq 1 40); do curl -sf "$BASE/healthz" 2>/dev/null | grep -q '"redis":true' && break; sleep 1; done
log "Redis 恢复: $(curl -s "$BASE/healthz")"

log "--- 停 PG：权威库不可用，30 次核验（并发10）必须全部失败关闭（503/超时，不得 200）"
"$CONTAINER_BIN" stop iam-pg17 >/dev/null 2>&1
sleep 2
CODES_TMP="$(mktemp -t c25codes)"
for i in $(seq 1 30); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -u "$CID:$CSEC" -H 'Content-Type: application/json' \
    -X POST "$PBASE/v1/internal/identity/introspect" \
    -d "{\"subject_token\":\"$TOKEN\",\"audience\":\"iam-admin\"}" || echo 000)
  echo "$c" >> "$CODES_TMP"
done
log -n "PG 停用时 introspect 状态码分布:"
sort "$CODES_TMP" | uniq -c | while read -r n code; do log -n " ${code}x${n}"; done; log ""
rm -f "$CODES_TMP"
"$CONTAINER_BIN" start iam-pg17 >/dev/null 2>&1
for i in $(seq 1 60); do curl -sf "$BASE/healthz" 2>/dev/null | grep -q '"postgres":true' && break; sleep 1; done
for i in $(seq 1 30); do curl -sf "$PBASE/healthz" 2>/dev/null | grep -q '"status":"ok"' && break; sleep 1; done
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$CID:$CSEC" \
  -H 'Content-Type: application/json' -X POST "$PBASE/v1/internal/identity/introspect" \
  -d "{\"subject_token\":\"$TOKEN\",\"audience\":\"iam-admin\"}")
log "PG 恢复后 introspect -> $code；主实例 $(curl -s "$BASE/healthz")"
log ""
log "说明：核验路径以 PG 为权威、每次实查（无正向授权 TTL 缓存，证据见 group4 B2 与会话集成测试）；"
log "本采集只含真实同机 HTTP 往返，无外部网络等待；队列/连接池为 HikariCP 暖连接 + 每线程 keep-alive。"
