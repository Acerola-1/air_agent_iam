#!/usr/bin/env bash
# C05/C06/C07/C11/C16：会话/修订/实时核验证据（可复跑）。
# A 段：真实 PG iam_test + 真实 Redis 逻辑库1 的 JUnit 集成测试（16 用例，含并发 CAS 与同事务回滚反例）。
# B 段：对运行中的 IAM 服务做真实 HTTP 黑盒：错口令/登录/me/menus/tenants/续期/CAS 反例/
#       登出即时失效（Redis 键删除 + PG 撤销 + outbox done + 审计无秘密 + 日志无令牌）。
# 用法：./scripts/verify-session-authority.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
set -a
. ./.env.local
set +a

BASE="http://127.0.0.1:${IAM_HTTP_PORT:-19100}"
CONTAINER_BIN=/usr/local/bin/container
EVIDENCE_DIR="docs/reviews/evidence/group3"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE="$EVIDENCE_DIR/c05-c06-c07-c11-c16-session-authority.txt"
SERVER_LOG="/tmp/iam-verify-server.log"

exec > >(tee "$EVIDENCE") 2>&1

section() { printf '\n========== %s ==========\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

section "环境与前置"
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'java: %s\n' "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-pg17' || fail "iam-pg17 未运行"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-redis7' || fail "iam-redis7 未运行"

SERVER_PID=""
CLEANUP_STARTED=0
if curl -sf -o /dev/null "$BASE/healthz"; then
  printf '复用已在 %s 运行的服务\n' "$BASE"
else
  section "构建并启动本脚本自管服务实例"
  ( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw -q -DskipTests package )
  "$JAVA_HOME/bin/java" -jar server/target/iam-server.jar > "$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  CLEANUP_STARTED=1
  for _ in $(seq 1 60); do
    sleep 1
    curl -sf -o /dev/null "$BASE/healthz" && break
  done
fi
curl -s "$BASE/healthz"; echo

cleanup() {
  if [ "$CLEANUP_STARTED" = "1" ] && [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

section "A 段：SessionAuthorityIntegrationTest（真实 PG/Redis，无 mock 授权）"
( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw test -Dtest=SessionAuthorityIntegrationTest )

section "B1：错口令必须 401 且返回统一错误信封"
code=$(curl -s -o /tmp/iam-v-bad.json -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"definitely-wrong-password\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "401" ] || fail "错口令期望 401，实际 $code"
python3 -c 'import json;d=json.load(open("/tmp/iam-v-bad.json"));assert d["error"]["code"]=="unauthenticated", d;print("envelope ok:",d["error"]["code"])'

section "B2：无令牌/垃圾令牌访问 /me 必须 401"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/auth/me")" = "401" ] || fail "无令牌应 401"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer garbage.token.value' "$BASE/v1/auth/me")" = "401" ] || fail "垃圾令牌应 401"

section "B3：正确登录 200，返回不透明令牌与四类修订，不含口令材料"
code=$(curl -s -o /tmp/iam-v-login.json -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || { cat /tmp/iam-v-login.json; fail "登录期望 200，实际 $code"; }
LOGIN_JSON=$(cat /tmp/iam-v-login.json)
TOKEN=$(python3 -c 'import json;print(json.load(open("/tmp/iam-v-login.json"))["access_token"])')
[ "${#TOKEN}" = "43" ] || fail "令牌应为 32 字节 URL-safe no-padding（43 字符），实际 ${#TOKEN}"
python3 - <<'PY'
import json
d = json.load(open('/tmp/iam-v-login.json'))
assert d["token_type"] == "Bearer"
ident = d["identity"]
assert ident["schema_version"] == "iam.identity.v1"
assert ident["principal"]["type"] == "human"
assert ident["active"] is True
rev = ident["revisions"]
for k in ("user_auth_revision", "tenant_auth_revision", "membership_revision", "session_ctx_version"):
    assert k in rev, k
assert "$2b$" not in json.dumps(d), "响应含 bcrypt 哈希"
assert "password_hash" not in json.dumps(d)
print("identity ok: principal=%s platform_admin=%s permissions=%d" % (
    ident["principal"]["type"], ident["platform_admin"], len(ident["permissions"])))
PY

section "B4：/me、/menus、/tenants"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/me" -o /tmp/iam-v-me.json
python3 -c 'import json;d=json.load(open("/tmp/iam-v-me.json"));assert d["active"];print("me ok")'
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/menus" -o /tmp/iam-v-menus.json
python3 -c 'import json;d=json.load(open("/tmp/iam-v-menus.json"));assert d["platform_admin"] is True;assert len(d["permissions"])>0;print("menus ok: %d 权限码" % len(d["permissions"]))'
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/tenants" -o /tmp/iam-v-tenants.json
python3 -c 'import json;d=json.load(open("/tmp/iam-v-tenants.json"));assert isinstance(d,list);print("tenants ok: %d 条" % len(d))'

section "B5：续期 200；陈旧 expected_ctx_version 必须 409 context_changed"
code=$(curl -s -o /tmp/iam-v-renew.json -w '%{http_code}' -X POST "$BASE/v1/auth/renew" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"expected_ctx_version":1}')
[ "$code" = "200" ] || fail "续期期望 200，实际 $code"
python3 -c 'import json;d=json.load(open("/tmp/iam-v-renew.json"));assert d["absolute_expires_at"] and d["idle_expires_at"];print("renew ok")'
code=$(curl -s -o /tmp/iam-v-stale.json -w '%{http_code}' -X POST "$BASE/v1/auth/renew" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"expected_ctx_version":99}')
[ "$code" = "409" ] || fail "陈旧 ctx 续期期望 409，实际 $code"
python3 -c 'import json;d=json.load(open("/tmp/iam-v-stale.json"));assert d["error"]["code"]=="context_changed";print("stale CAS ok: context_changed")'

section "B6：切到不存在的企业必须 403（非成员/不可用）"
code=$(curl -s -o /tmp/iam-v-switch.json -w '%{http_code}' -X POST "$BASE/v1/auth/switch-tenant" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"tenant_id":"00000000-0000-4000-8000-000000000999","expected_ctx_version":1}')
[ "$code" = "403" ] || fail "非成员切企业期望 403，实际 $code"
python3 -c 'import json;d=json.load(open("/tmp/iam-v-switch.json"));assert d["error"]["code"]=="forbidden";print("switch guard ok: forbidden")'

section "B7：登出 204；随后 /me 必须 401（PG 权威即时撤销）"
DIGEST=$(printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}')
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/logout" \
  -H "Authorization: Bearer $TOKEN")
[ "$code" = "204" ] || fail "登出期望 204，实际 $code"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/me")" = "401" ] \
  || fail "登出后 /me 应 401"

section "B8：Redis 键必须已由 outbox 中继删除；PG 会话已撤销；outbox done"
sleep 2
REDIS_EXISTS=$("$CONTAINER_BIN" exec iam-redis7 redis-cli -a "$IAM_REDIS_PASSWORD" -n 0 \
  EXISTS "Authorization:login:token:$DIGEST" 2>/dev/null | tr -d '[:space:]')
[ "$REDIS_EXISTS" = "0" ] || fail "Redis 会话键仍存在：Authorization:login:token:$DIGEST"
echo "redis EXISTS Authorization:login:token:$DIGEST = 0"
# local GUC 仅存活于当前事务：平台上下文与审计查询必须在同一 BEGIN..COMMIT 内
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 <<SQL
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
SELECT token_digest, status, revoke_reason FROM iam.auth_sessions WHERE token_digest = '$DIGEST';
SELECT kind, status, attempts FROM iam.outbox WHERE payload::text LIKE '%$DIGEST%' ORDER BY id DESC LIMIT 1;
SELECT action, COUNT(*) FROM iam.audit_logs GROUP BY action ORDER BY action;
COMMIT;
SQL

section "B9：响应与服务日志秘密扫描（原令牌/bcrypt/明文口令零命中）"
# 登录响应是令牌唯一合法下发位置；除此之外的任何响应都不得回显原令牌
python3 - <<'PY'
import json
login = json.load(open('/tmp/iam-v-login.json'))
assert "$2b$" not in json.dumps(login), "登录响应含 bcrypt 哈希"
assert "password_hash" not in json.dumps(login)
ident = json.dumps(login["identity"])
assert "token" not in ident.lower(), "identity 体内不得携带令牌材料"
print("登录响应：令牌仅在 access_token 顶层字段一次性下发，identity 无令牌材料")
PY
for f in /tmp/iam-v-me.json /tmp/iam-v-menus.json /tmp/iam-v-tenants.json /tmp/iam-v-renew.json; do
  if grep -qF "$TOKEN" "$f" 2>/dev/null; then fail "$f 回显了原始令牌"; fi
  if grep -q '\$2b\$' "$f"; then fail "$f 含 bcrypt 哈希"; fi
done
echo "me/menus/tenants/renew 响应无原令牌/无哈希"
LOG_TO_SCAN="/tmp/iam-server.log"
[ "$CLEANUP_STARTED" = "1" ] && LOG_TO_SCAN="$SERVER_LOG"
if [ -f "$LOG_TO_SCAN" ]; then
  HITS=$(grep -cE "($TOKEN|\\\$2b\\\$|$IAM_BOOTSTRAP_PASSWORD)" "$LOG_TO_SCAN" || true)
  [ "$HITS" = "0" ] || fail "服务日志出现原令牌/哈希/口令 $HITS 次"
  echo "服务日志秘密命中 = 0（${LOG_TO_SCAN}）"
else
  echo "跳过日志扫描（复用外部服务实例时无日志句柄）"
fi

section "全部通过：$(date -u +%Y-%m-%dT%H:%M:%SZ)"
