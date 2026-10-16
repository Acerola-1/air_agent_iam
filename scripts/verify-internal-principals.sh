#!/usr/bin/env bash
# C12/C13/C03/C15/C14：内部客户端/verification_ref/rt-v1/服务账号/限流/依赖故障证据（可复跑）。
# A 段：真实 PG iam_test + 真实 Redis 逻辑库1 的 JUnit 集成测试（InternalClient 23 + RateLimit 2）。
# B 段：对自管 jar 实例做真实 HTTP 黑盒（curl Basic 认证 + Python 跨语言验票）：
#   B1 客户端凭据错 401 / scope 不足 403 / 受众白名单 403 / 垃圾主体 200 inactive
#   B2 人类令牌 introspect active（PG 权威，不查 Redis 正向缓存）
#   B3 切企业 + rt-v1 签票 200，Python 侧用 IAM_RT_KEYS_SECRET 原字节验签通过（C03 双向）
#   B4 verification_ref 复查：active/context_matches -> 篡改修订 revision_mismatch -> 登出后 invalid_or_revoked
#   B5 服务账号：建档 201（平台权）-> 机器令牌 introspect 主体分型 -> 机器令牌签 rt 票 401
#      -> 资源型权限建档 400 -> 吊销后 200 inactive
#   B6 登录限流：同主体第 11 次错误登录必须 429
#   B7 Redis 故障失败关闭：停 iam-redis7 后登录必须 503；恢复后登录恢复 200
#   B8 响应/日志秘密扫描：客户端密钥/SA 明文密钥/rt 密钥/原令牌零命中
# 用法：./scripts/verify-internal-principals.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
set -a
. ./.env.local
set +a

BASE="http://127.0.0.1:${IAM_HTTP_PORT:-19100}"
CONTAINER_BIN=/usr/local/bin/container
EVIDENCE_DIR="docs/reviews/evidence/group4"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE="$EVIDENCE_DIR/c12-c13-c03-c15-internal-principals.txt"
SERVER_LOG="/tmp/iam-verify-internal-server.log"
TMPDIR_RUN="$(mktemp -d)"

exec > >(tee "$EVIDENCE") 2>&1

section() { printf '\n========== %s ==========\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
# sha256 hex（OpaqueTokens.digest 同构）
sha256hex() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

section "环境与前置"
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'java: %s\n' "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-pg17' || fail "iam-pg17 未运行"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-redis7' || fail "iam-redis7 未运行"

SUFFIX="$(date +%H%M%S)$((RANDOM%1000))"
READ_CLIENT="verify-read-$SUFFIX"
READ_SECRET="read-secret-$SUFFIX-0123456789abcdef01234"
KNOW_CLIENT="verify-know-$SUFFIX"
KNOW_SECRET="know-secret-$SUFFIX-0123456789abcdef0123456"
NOSCOPE_CLIENT="verify-noscope-$SUFFIX"
NOSCOPE_SECRET="noscope-$SUFFIX-0123456789abcdef01234567"
TENANT_CODE="VERIFY-$SUFFIX"
TENANT_ID="$(uuidgen | tr 'A-Z' 'a-z')"
MEMBER_ID="$(uuidgen | tr 'A-Z' 'a-z')"

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
  rm -rf "$TMPDIR_RUN"
}
trap cleanup EXIT

section "B0：种子数据（migrate 角色，平台上下文单事务）"
# 三个内部客户端：read(iam-admin 受众/introspect)、knowledge(knowledge 受众/introspect)、noscope(无 scope)
# 一个测试企业 + bootstrap 用户的活跃成员关系（供切企业/签 rt 票）
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 <<SQL
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences)
VALUES ('$READ_CLIENT','$READ_CLIENT','$(sha256hex "$READ_SECRET")',
        ARRAY['identity:introspect']::text[], ARRAY['iam-admin']::text[]),
       ('$KNOW_CLIENT','$KNOW_CLIENT','$(sha256hex "$KNOW_SECRET")',
        ARRAY['identity:introspect']::text[], ARRAY['knowledge']::text[]),
       ('$NOSCOPE_CLIENT','$NOSCOPE_CLIENT','$(sha256hex "$NOSCOPE_SECRET")',
        ARRAY[]::text[], ARRAY['iam-admin']::text[]);
INSERT INTO iam.tenants(id, code, name, created_by)
SELECT '$TENANT_ID','$TENANT_CODE','验证企业', id
FROM iam.users
WHERE account='$IAM_BOOTSTRAP_ACCOUNT'
  AND NOT EXISTS (SELECT 1 FROM iam.tenants WHERE code='$TENANT_CODE');
INSERT INTO iam.tenant_memberships(id, tenant_id, user_id)
SELECT '$MEMBER_ID','$TENANT_ID',id FROM iam.users WHERE account='$IAM_BOOTSTRAP_ACCOUNT'
ON CONFLICT DO NOTHING;
SELECT count(*) AS seeded_clients FROM iam.internal_clients WHERE client_id LIKE 'verify-%-$SUFFIX';
COMMIT;
SQL
basic_auth() { printf 'Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
H_READ="-H $(basic_auth "$READ_CLIENT" "$READ_SECRET")"

section "A 段：InternalClientIntegrationTest(23) + RateLimitIntegrationTest(2)，真实 PG/Redis"
( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw test -Dtest='InternalClientIntegrationTest,RateLimitIntegrationTest' )

section "B1：客户端认证失败模式（凭据错 401 / scope 不足 403 / 受众白名单 403 / 垃圾主体 200 inactive）"
code=$(curl -s -o "$TMPDIR_RUN/badclient.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$READ_CLIENT" wrong-secret)" -H 'Content-Type: application/json' \
  -d '{"subject_token":"x","audience":"iam-admin"}')
[ "$code" = "401" ] || fail "错客户端密钥期望 401，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/badclient.json"));assert d["error"]["code"]=="unauthenticated",d;print("错密钥 401:",d["error"]["message"])'

code=$(curl -s -o "$TMPDIR_RUN/noscope.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$NOSCOPE_CLIENT" "$NOSCOPE_SECRET")" -H 'Content-Type: application/json' \
  -d '{"subject_token":"x","audience":"iam-admin"}')
[ "$code" = "403" ] || fail "无 scope 期望 403，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/noscope.json"));assert d["error"]["code"]=="forbidden";print("scope 不足 403 ok")'

code=$(curl -s -o "$TMPDIR_RUN/badaud.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$READ_CLIENT" "$READ_SECRET")" -H 'Content-Type: application/json' \
  -d '{"subject_token":"x","audience":"not-registered-aud"}')
[ "$code" = "403" ] || fail "客户端未注册受众期望 403，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/badaud.json"));print("受众白名单 403:",d["error"]["message"])'

code=$(curl -s -o "$TMPDIR_RUN/garbage.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$READ_CLIENT" "$READ_SECRET")" -H 'Content-Type: application/json' \
  -d '{"subject_token":"definitely-not-a-real-token","audience":"iam-admin"}')
[ "$code" = "200" ] || fail "垃圾主体期望 200 inactive，实际 $code"
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/garbage.json"))
assert d["schema_version"]=="iam.introspection.v1", d
assert d["active"] is False and d["reason"]=="invalid_or_revoked", d
print("垃圾主体 200 inactive:", d["reason"], d["schema_version"])
PY

section "B2：人类登录 → introspect 200 active（每次读 PG，无正向授权 TTL 缓存）"
code=$(curl -s -o "$TMPDIR_RUN/login.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/login.json"; fail "登录期望 200，实际 $code"; }
TOKEN=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/login.json"))["access_token"])')
code=$(curl -s -o "$TMPDIR_RUN/intro.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$READ_CLIENT" "$READ_SECRET")" -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$TOKEN\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/intro.json"; fail "人类 introspect 期望 200，实际 $code"; }
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/intro.json"))
assert d["active"] is True and d["principal"]["type"]=="human", d
assert d["user"] is not None and d["session"] is not None
print("人类主体 active: principal=%s 权限数=%d" % (d["principal"]["type"], len(d["permissions"])))
PY

section "B3：切企业 → rt-v1 签票 200，Python 用真实 IAM_RT_KEYS_SECRET 原字节验签（C03 双向）"
code=$(curl -s -o "$TMPDIR_RUN/switch.json" -w '%{http_code}' -X POST "$BASE/v1/auth/switch-tenant" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"expected_ctx_version\":1}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/switch.json"; fail "切企业期望 200，实际 $code"; }
echo "switch-tenant 200 ctx_version=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/switch.json")).get("context_version","?"))')"
code=$(curl -s -o "$TMPDIR_RUN/ticket.json" -w '%{http_code}' -X POST "$BASE/v1/internal/runtime-tickets" \
  -H "Authorization: $(basic_auth "$IAM_INTERNAL_RUNTIME_CLIENT_ID" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET")" \
  -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$TOKEN\",\"audience\":\"langgraph-runtime\",\"target_tenant_id\":\"$TENANT_ID\",\"expected_ctx_version\":2}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/ticket.json"; fail "rt 签票期望 200，实际 $code"; }
python3 - <<PY
import json, os, sys
sys.path.insert(0, "tools/rt-v1")
import rt_v1
d=json.load(open("$TMPDIR_RUN/ticket.json"))
assert d["format"]=="rt-v1" and d["token_type"]=="Bearer" and d["audience"]=="langgraph-runtime"
assert d["expires_in"]==60, d
secret=os.environ["IAM_RT_KEYS_SECRET"].encode("utf-8")
ok, reason, body = rt_v1.verify(d["ticket"], os.environ["IAM_RT_KEYS_KID"], secret, "langgraph-runtime")
assert ok, (reason, d["ticket"])
assert body["aud"]=="langgraph-runtime"
# 改一个字节必须验签失败
bad = d["ticket"][:-2] + ("aa" if d["ticket"][-2:]!="aa" else "bb")
ok2, reason2, _ = rt_v1.verify(bad, os.environ["IAM_RT_KEYS_KID"], secret, "langgraph-runtime")
assert not ok2 and reason2=="bad_signature"
# 错误受众拒绝
ok3, reason3, _ = rt_v1.verify(d["ticket"], os.environ["IAM_RT_KEYS_KID"], secret, "knowledge")
assert not ok3 and reason3=="bad_audience"
print("rt-v1 Python 验签 ok: sid=%s tid=%s crev=%d 篡改/错受众均拒绝" % (
    body["sid"][:8], body["tid"][:8], body["crev"]))
PY

section "B4：verification_ref 长运行引用：复查 active → 篡改修订 revision_mismatch → 登出后 invalid_or_revoked（C13）"
code=$(curl -s -o "$TMPDIR_RUN/ref.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$IAM_INTERNAL_RUNTIME_CLIENT_ID" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET")" \
  -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$TOKEN\",\"audience\":\"langgraph-runtime\",\"include_execution_context\":true}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/ref.json"; fail "取 execution_context 期望 200，实际 $code"; }
python3 - "$TMPDIR_RUN" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]+"/ref.json"))
ec=d["execution_context"]
assert ec["verification_ref"] and ec["valid_until"], ec
rev=ec["revisions"]
json.dump({"ref":ec["verification_ref"],"rev":rev}, open(sys.argv[1]+"/refparts.json","w"))
print("verification_ref 已签发（响应不含任何会话原令牌）:", ec["verification_ref"][:13], "...")
PY
python3 - "$TMPDIR_RUN" "$BASE" "$IAM_INTERNAL_RUNTIME_CLIENT_ID" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET" <<'PY'
import json, subprocess, sys, urllib.request, base64
tmp, base, cid, csec = sys.argv[1:5]
parts=json.load(open(tmp+"/refparts.json"))
def call(payload):
    req=urllib.request.Request(base+"/v1/internal/identity/introspect",
        data=json.dumps(payload).encode(),
        headers={"Content-Type":"application/json",
                 "Authorization":"Basic "+base64.b64encode(f"{cid}:{csec}".encode()).decode()},
        method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
rev=parts["rev"]
# 1) 存储修订 + 全量期望修订：active/context_matches
payload={"execution_context":{"verification_ref":parts["ref"],
    "expected_revisions":rev},"audience":"langgraph-runtime"}
st,d=call(payload)
assert st==200 and d["active"] is True and d["context_matches"] is True, (st,d)
print("复查 active: revisions session_ctx=%s" % d["revisions"]["session_ctx_version"])
# 2) 篡改 user_auth_revision：必须 revision_mismatch
bad=dict(rev); bad["user_auth_revision"]=bad["user_auth_revision"]+100
st,d=call({"execution_context":{"verification_ref":parts["ref"],"expected_revisions":bad},
           "audience":"langgraph-runtime"})
assert st==200 and d["active"] is False and d["reason"]=="revision_mismatch", (st,d)
print("篡改修订 -> inactive:", d["reason"])
# 3) 不存在的 ref：invalid_or_revoked
st,d=call({"execution_context":{"verification_ref":"00000000-0000-4000-8000-000000000000",
    "expected_revisions":rev},"audience":"langgraph-runtime"})
assert st==200 and d["active"] is False and d["reason"]=="invalid_or_revoked", (st,d)
print("未知 ref -> inactive:", d["reason"])
PY
# 登出（即时撤销）后复查同一 ref：必须 inactive
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/logout" -H "Authorization: Bearer $TOKEN")
[ "$code" = "204" ] || fail "登出期望 204，实际 $code"
python3 - "$TMPDIR_RUN" "$BASE" "$IAM_INTERNAL_RUNTIME_CLIENT_ID" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET" <<'PY'
import json, sys, urllib.request, base64
tmp, base, cid, csec = sys.argv[1:5]
parts=json.load(open(tmp+"/refparts.json"))
req=urllib.request.Request(base+"/v1/internal/identity/introspect",
    data=json.dumps({"execution_context":{"verification_ref":parts["ref"],
        "expected_revisions":parts["rev"]},"audience":"langgraph-runtime"}).encode(),
    headers={"Content-Type":"application/json",
             "Authorization":"Basic "+base64.b64encode(f"{cid}:{csec}".encode()).decode()},
    method="POST")
with urllib.request.urlopen(req) as r:
    d=json.loads(r.read())
assert d["active"] is False and d["reason"]=="invalid_or_revoked", d
print("登出即时撤销后复查 -> inactive:", d["reason"])
PY

section "B5：服务账号分型（C15）：建档/机器主体形状/机器令牌禁止签票/资源型权限拒绝/吊销即时失效"
# 重新登录拿平台令牌（上个令牌已登出）
code=$(curl -s -o "$TMPDIR_RUN/login2.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || fail "第二次登录失败 $code"
PTOKEN=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/login2.json"))["access_token"])')
SA_ACCOUNT="sa-verify-$SUFFIX"
code=$(curl -s -o "$TMPDIR_RUN/sa.json" -w '%{http_code}' -X POST "$BASE/v1/admin/service-accounts" \
  -H "Authorization: Bearer $PTOKEN" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$SA_ACCOUNT\",\"name\":\"验证服务账号\",\"tenant_id\":\"$TENANT_ID\",\"audiences\":[\"knowledge\"],\"expires_in_days\":90,\"permissions\":[\"tenant:member:read\"]}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/sa.json"; fail "建档期望 200，实际 $code"; }
SA_ID=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/sa.json"))["id"])')
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/sa.json"))
assert d["status"]=="active" and d["audiences"]==["knowledge"]
assert d["permissions"]==["tenant:member:read"], d
assert "secret" not in json.dumps(d).lower() or "client_secret" not in json.dumps(d)
print("服务账号已建档: id=%s 权限=%s" % (d["id"][:13], d["permissions"]))
PY
code=$(curl -s -o "$TMPDIR_RUN/satok.json" -w '%{http_code}' -X POST "$BASE/v1/admin/service-accounts/$SA_ID/tokens" \
  -H "Authorization: Bearer $PTOKEN" -H 'Content-Type: application/json' -d '{"overlap_hours":0}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/satok.json"; fail "签发机器令牌期望 200，实际 $code"; }
SA_SECRET=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/satok.json"))["secret"])')
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/satok.json"))
assert set(["credential_id","secret","credential_revision","expires_at"]).issubset(d), d
assert d["credential_revision"]==1 and len(d["secret"])==43
print("机器凭据仅一次明文: %s... rev=%s" % (d["credential_id"][:12], d["credential_revision"]))
PY
code=$(curl -s -o "$TMPDIR_RUN/saintro.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$KNOW_CLIENT" "$KNOW_SECRET")" -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$SA_SECRET\",\"audience\":\"knowledge\"}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/saintro.json"; fail "机器 introspect 期望 200，实际 $code"; }
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/saintro.json"))
assert d["active"] is True, d
p=d["principal"]; assert p["type"]=="service_account" and p["realm"]=="service", p
assert d["user"] is None and d["session"] is None and d["membership"] is None, d
assert d["current_tenant"]["id"]=="$TENANT_ID"
assert d["permissions"]==["tenant:member:read"], d["permissions"]
assert d["revisions"] is None, d
assert d["credential_revision"]==1 and d["credential_id"].startswith("sak_")
assert "knowledge:lib" not in json.dumps(d["permissions"]), "资源型权限不得授予"
print("机器主体形状 ok: type=%s realm=%s 人类字段全 null 权限=%s" % (p["type"],p["realm"],d["permissions"]))
PY
# 机器令牌签 rt 票必须 401（机器不能签人类运行票据）
code=$(curl -s -o "$TMPDIR_RUN/saticket.json" -w '%{http_code}' -X POST "$BASE/v1/internal/runtime-tickets" \
  -H "Authorization: $(basic_auth "$IAM_INTERNAL_RUNTIME_CLIENT_ID" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET")" \
  -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$SA_SECRET\",\"audience\":\"langgraph-runtime\",\"target_tenant_id\":\"$TENANT_ID\",\"expected_ctx_version\":2}")
[ "$code" = "401" ] || fail "机器令牌签 rt 票期望 401，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/saticket.json"));print("机器签票拒绝:",d["error"]["code"])'
# 资源型权限建档：应用层 400
code=$(curl -s -o "$TMPDIR_RUN/sares.json" -w '%{http_code}' -X POST "$BASE/v1/admin/service-accounts" \
  -H "Authorization: Bearer $PTOKEN" -H 'Content-Type: application/json' \
  -d "{\"account\":\"sa-res-$SUFFIX\",\"name\":\"资源越权\",\"tenant_id\":\"$TENANT_ID\",\"audiences\":[\"knowledge\"],\"expires_in_days\":90,\"permissions\":[\"knowledge:lib:air:read\"]}")
[ "$code" = "400" ] || fail "资源型权限期望 400，实际 $code"
TMPDIR_RUN="$TMPDIR_RUN" python3 - <<'PY'
import json, os
d=json.load(open(os.environ["TMPDIR_RUN"]+"/sares.json"))
print("资源型权限应用层拒绝:", d["error"]["message"])
PY
# DB 触发器同构反例（绕过应用直插必须 23514）
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=0 2>&1 <<SQL | tee "$TMPDIR_RUN/trigger.out"
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
DO \$\$
BEGIN
  INSERT INTO iam.service_account_permissions(tenant_id, service_account_id, permission_id, granted_by)
  SELECT '$TENANT_ID','$SA_ID','01930000-0000-4000-8000-000000000201',
         (SELECT id FROM iam.users WHERE account='$IAM_BOOTSTRAP_ACCOUNT');
EXCEPTION
  WHEN check_violation THEN
    RAISE NOTICE 'TRIGGER_CHECK_VIOLATION_OK sqlstate=%', SQLSTATE;
END \$\$;
ROLLBACK;
SQL
grep -q 'TRIGGER_CHECK_VIOLATION_OK sqlstate=23514' "$TMPDIR_RUN/trigger.out" || fail "DB 触发器未以 23514 拒绝资源型权限"
# 吊销机器凭据 → introspect 立即 inactive
SAK=$(TMPDIR_RUN="$TMPDIR_RUN" python3 - <<'PY'
import json, os
print(json.load(open(os.environ["TMPDIR_RUN"]+"/satok.json"))["credential_id"])
PY
)
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/admin/service-accounts/tokens/$SAK/revoke" \
  -H "Authorization: Bearer $PTOKEN")
[ "$code" = "204" ] || fail "吊销期望 204，实际 $code"
code=$(curl -s -o "$TMPDIR_RUN/sarevoked.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
  -H "Authorization: $(basic_auth "$KNOW_CLIENT" "$KNOW_SECRET")" -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$SA_SECRET\",\"audience\":\"knowledge\"}")
[ "$code" = "200" ] || fail "吊销后 introspect 期望 200，实际 $code"
python3 - <<PY
import json
d=json.load(open("$TMPDIR_RUN/sarevoked.json"))
assert d["active"] is False and d["reason"]=="invalid_or_revoked", d
print("吊销即时生效 -> inactive:", d["reason"])
PY

section "B6：登录限流失败关闭：同主体连续错误登录，窗口内第 11 次必须 429"
got429=0
for i in $(seq 1 12); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"account\":\"ratehit-$SUFFIX\",\"password\":\"definitely-wrong-password\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
  if [ "$code" = "429" ]; then got429=1; echo "第 $i 次返回 429（阈值 10/min）"; break; fi
done
[ "$got429" = "1" ] || fail "未在窗口内观察到 429"

section "B7：Redis 故障必须失败关闭（登录 503），恢复后自动复原"
"$CONTAINER_BIN" stop iam-redis7 >/dev/null
sleep 2
code=$(curl -s -o "$TMPDIR_RUN/no-redis.json" -w '%{http_code}' --max-time 10 -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}" || echo "000")
echo "Redis 停止时登录 HTTP=$code"
[ "$code" = "503" ] || { cat "$TMPDIR_RUN/no-redis.json"; fail "Redis 故障期望 503 失败关闭，实际 $code"; }
TMPDIR_RUN="$TMPDIR_RUN" python3 - <<'PY'
import json, os
d=json.load(open(os.environ["TMPDIR_RUN"]+"/no-redis.json"))
print("失败关闭:", d["error"]["code"], d["error"].get("message", ""))
PY
"$CONTAINER_BIN" start iam-redis7 >/dev/null
for _ in $(seq 1 30); do
  "$CONTAINER_BIN" exec iam-redis7 redis-cli -a "$IAM_REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG && break
  sleep 1
done
# Redis PONG 后 Lettuce 连接重连存在短暂窗口：轮询登录直到恢复（失败关闭期间持续 503 是正确行为）
recovered=0
for i in $(seq 1 30); do
  code=$(curl -s -o "$TMPDIR_RUN/recovered.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
  if [ "$code" = "200" ]; then recovered=1; echo "Redis 恢复后第 ${i} 次轮询登录 200（服务自愈未重启）"; break; fi
  sleep 1
done
[ "$recovered" = "1" ] || fail "Redis 恢复后 30 秒内登录未恢复，末次 HTTP=$code"

section "B8：响应与服务日志秘密扫描（SA 明文密钥/客户端密钥/rt 密钥/原令牌零命中）"
for f in "$TMPDIR_RUN"/*.json; do
  for secret in "$SA_SECRET" "$READ_SECRET" "$KNOW_SECRET" "$NOSCOPE_SECRET" "$IAM_INTERNAL_RUNTIME_CLIENT_SECRET" "$IAM_RT_KEYS_SECRET"; do
    if grep -qF "$secret" "$f" 2>/dev/null; then
      case "$f" in
        *satok.json) [ "$secret" = "$SA_SECRET" ] && continue ;;
      esac
      fail "$(basename "$f") 泄露秘密（$secret 前 8 位 ${secret:0:8}）"
    fi
  done
done
echo "响应文件：机器明文密钥只出现在 satok.json 一次性下发位置"
LOG_TO_SCAN="/tmp/iam-server.log"
[ "$CLEANUP_STARTED" = "1" ] && LOG_TO_SCAN="$SERVER_LOG"
if [ -f "$LOG_TO_SCAN" ]; then
  HITS=$(grep -cE "($SA_SECRET|$READ_SECRET|$KNOW_SECRET|$NOSCOPE_SECRET|$IAM_INTERNAL_RUNTIME_CLIENT_SECRET|$IAM_RT_KEYS_SECRET|\\\$2b\\\$)" "$LOG_TO_SCAN" || true)
  [ "$HITS" = "0" ] || fail "服务日志秘密命中 $HITS 次"
  echo "服务日志秘密命中 = 0（${LOG_TO_SCAN}）"
else
  echo "跳过日志扫描（复用外部服务实例时无日志句柄）"
fi

section "全部通过：$(date -u +%Y-%m-%dT%H:%M:%SZ)"
