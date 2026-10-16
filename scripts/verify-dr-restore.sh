#!/usr/bin/env bash
# 7.3 自有 iam 库备份/恢复 + 撤销重施演练（可复跑）。
# 不触碰两 Python 仓库与任何源库；恢复目标是同集群一次性 SCRATCH 库 + Redis 逻辑库3 +
# 19102 第二实例，演练结束即销毁；19100 主实例全程不动。
set -u
cd "$(dirname "$0")/.."
: "${IAM_HTTP_PORT:=19100}"
BASE="http://127.0.0.1:${IAM_HTTP_PORT}"
RBASE="http://127.0.0.1:19102"
CONTAINER_BIN=/usr/local/bin/container
OUT="docs/reviews/evidence/group7"
mkdir -p "$OUT"
EVID="$OUT/dr-restore.txt"
: "${IAM_BOOTSTRAP_ACCOUNT:?需 source .env.local}"
: "${IAM_BOOTSTRAP_PASSWORD:?需 source .env.local}"
: "${IAM_PG_MIGRATE_USER:?}"
: "${IAM_REDIS_PASSWORD:?}"
JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
S="$((RANDOM%900000+100000))"
U_ACC="uia-dr-$S"; U_PW="Drill-Pass-$S-z"; NEW_PW="Drill-New-$S-z"
CID="dr-read-$S"; CSEC="dr-secret-$S-z"
SCRATCH="iam_dr_$S"
DUMP="/tmp/iam-dr-$S.dump"
RPID=""
sha256hex() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }
j() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))' "$1"; }

api() { # method path token [data] -> "code body"
  local m="$1" p="$2" t="$3" d="${4:-}"
  if [ -n "$d" ]; then
    curl -s -w '\n%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" \
      -H 'Content-Type: application/json' -d "$d"
  else
    curl -s -w '\n%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t"
  fi
}
rapi() { # same against recovered instance
  local m="$1" p="$2" t="$3" d="${4:-}"
  if [ -n "$d" ]; then
    curl -s -w '\n%{http_code}' -X "$m" "$RBASE$p" -H "Authorization: Bearer $t" \
      -H 'Content-Type: application/json' -d "$d"
  else
    curl -s -w '\n%{http_code}' -X "$m" "$RBASE$p" -H "Authorization: Bearer $t"
  fi
}
intro() { # base client token  -> code
  local b="$1"
  curl -s -o /tmp/dr-intro.json -w '%{http_code}' -X POST "$b/v1/internal/identity/introspect" \
    -u "$CID:$CSEC" -H 'Content-Type: application/json' \
    -d "{\"subject_token\":\"$2\",\"audience\":\"iam-admin\"}"
}
assert_eq() { [ "$1" = "$2" ] || { echo "断言失败: 期望 $2 实际 $1 — $3"; fail=1; }; }

cleanup() {
  [ -n "$RPID" ] && kill "$RPID" 2>/dev/null || true
  "$CONTAINER_BIN" exec -i iam-pg17 psql -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL || true
DROP DATABASE IF EXISTS $SCRATCH;
SQL
  # internal_clients 在主库，DROP 后再连主库删
  "$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL || true
BEGIN; SELECT iam_auth.set_request_context(NULL,NULL,true);
DELETE FROM iam.internal_clients WHERE client_id='$CID';
UPDATE iam.users SET status='disabled' WHERE account LIKE 'uia-dr-%';
COMMIT;
SQL
  rm -f "$DUMP" /tmp/dr-intro.json
}
trap cleanup EXIT
fail=0

: > "$EVID"
log() { echo "$@" | tee -a "$EVID"; }

log "=== 7.3 备份/恢复/撤销重施演练 $(date -u +%FT%TZ)（后缀 ${S}） ==="

log "--- 1. 种子内部客户端 + 建档演习用户（主实例 19100）"
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 >>"$EVID" 2>&1 <<SQL
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
INSERT INTO iam.internal_clients(client_id,name,secret_digest,scopes,audiences)
VALUES ('$CID','$CID','$(sha256hex "$CSEC")',
        ARRAY['identity:introspect']::text[], ARRAY['iam-admin']::text[]);
COMMIT;
SQL

PTOK=$(curl -s -X POST "$BASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}" \
  | j 'd["access_token"]')
[ -n "$PTOK" ] || { log "平台登录失败"; exit 1; }

resp=$(api POST /v1/admin/users "$PTOK" \
  "{\"account\":\"$U_ACC\",\"display_name\":\"灾备演习用户\",\"password\":\"$U_PW\"}")
code=$(echo "$resp" | tail -1); body=$(echo "$resp" | sed '$d')
assert_eq "$code" 201 "建档"
UID_=$(echo "$body" | j 'd["id"]'); REV=$(echo "$body" | j 'd["auth_revision"]')
log "建档 201 id=${UID_:0:8}… revision=$REV"

resp=$(api POST "/v1/admin/users/$UID_/platform-roles" "$PTOK" \
  "{\"role_codes\":[\"platform_auditor\"],\"expected_revision\":$REV}")
code=$(echo "$resp" | tail -1); body=$(echo "$resp" | sed '$d')
assert_eq "$code" 200 "授予 platform_auditor"
REV=$(echo "$body" | j 'd["auth_revision"]')
log "授权 200 platform_auditor revision=$REV"

T1=$(curl -s -X POST "$BASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$U_ACC\",\"password\":\"$U_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}" \
  | j 'd["access_token"]')
code=$(intro "$BASE" "$T1"); assert_eq "$code" 200 "备份前 introspect"
grep -q '"active":true' /tmp/dr-intro.json && log "T1 active，权限数=$(python3 -c 'import json;print(len(json.load(open("/tmp/dr-intro.json"))["permissions"]))')，含 platform:audit:read=$(python3 -c 'import json;print("platform:audit:read" in json.load(open("/tmp/dr-intro.json"))["permissions"])')"

log "--- 2. 备份（pg_dump custom format，文件不进版本库）"
"$CONTAINER_BIN" exec -i iam-pg17 pg_dump -U postgres -d iam -Fc > "$DUMP"
log "dump: $(ls -l "$DUMP" | awk '{print $5}') 字节 sha256=$(shasum -a 256 "$DUMP" | awk '{print $1}')"

log "--- 3. 备份后变更（模拟灾备窗口内的真实撤销）：重置密码 + 移除平台角色"
code=$(api POST "/v1/admin/users/$UID_/password" "$PTOK" "{\"new_password\":\"$NEW_PW\"}" | tail -1)
assert_eq "$code" 204 "重置密码"
code=$(intro "$BASE" "$T1"); assert_eq "$code" 200 "撤销后 introspect HTTP"
python3 -c 'import json;d=json.load(open("/tmp/dr-intro.json"));assert d["active"] is False and d["reason"]=="invalid_or_revoked",d;print("T1 已即时撤销:",d["reason"])' | tee -a "$EVID"
REV=$(api GET "/v1/admin/users/$UID_" "$PTOK" | sed '$d' | j 'd["auth_revision"]')
resp=$(api POST "/v1/admin/users/$UID_/platform-roles" "$PTOK" \
  "{\"role_codes\":[],\"expected_revision\":$REV}")
assert_eq "$(echo "$resp" | tail -1)" 200 "移除角色"
log "主实例撤销完成（重置密码→旧会话 invalid_or_revoked；角色已清空）"

log "--- 4. 恢复到一次性 SCRATCH 库 ${SCRATCH}（主库不动）"
"$CONTAINER_BIN" exec -i iam-pg17 psql -U postgres -d postgres -v ON_ERROR_STOP=1 >>"$EVID" 2>&1 <<SQL
CREATE DATABASE $SCRATCH OWNER $IAM_PG_MIGRATE_USER;
SQL
"$CONTAINER_BIN" exec -i iam-pg17 pg_restore -U "$IAM_PG_MIGRATE_USER" -d "$SCRATCH" --no-owner --exit-on-error < "$DUMP" >>"$EVID" 2>&1
"$CONTAINER_BIN" exec -i iam-redis7 redis-cli -a "$IAM_REDIS_PASSWORD" -n 3 FLUSHDB >/dev/null 2>&1
log "scratch 库已恢复；Redis 逻辑库3 已清空（0 库不动）"

log "--- 5. 第二实例 19102 挂 scratch 库启动"
set -a; . ./.env.local; set +a
IAM_HTTP_PORT=19102 IAM_PG_DB="$SCRATCH" IAM_REDIS_DB=3 \
  "$JAVA_HOME/bin/java" -jar server/target/iam-server.jar > /tmp/dr-recovered.log 2>&1 &
RPID=$!
for i in $(seq 1 60); do
  h=$(curl -s "$RBASE/healthz" 2>/dev/null)
  echo "$h" | grep -q '"status":"ok"' && { log "恢复实例就绪: $h"; break; }
  sleep 1
done
[ "$(curl -s "$RBASE/healthz" | j 'd.get("status","")' 2>/dev/null)" = "ok" ] || { log "恢复实例未就绪"; tail -20 /tmp/dr-recovered.log | tee -a "$EVID"; exit 1; }

log "--- 6. 恢复点确认：备份时的状态回来了（T1 active、auditor 权限在）"
code=$(intro "$RBASE" "$T1"); assert_eq "$code" 200 "恢复实例 introspect"
python3 - <<'PY' | tee -a "$EVID"
import json
d=json.load(open("/tmp/dr-intro.json"))
assert d["active"] is True, d
assert "platform:audit:read" in d["permissions"], d["permissions"]
print("恢复点状态一致: active=True, platform:audit:read 存在, 权限数=%d" % len(d["permissions"]))
PY

log "--- 7. 撤销重施（runbook：按审计事件顺序，在恢复实例补放备份后的撤销）"
PTOK2=$(curl -s -X POST "$RBASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}" \
  | j 'd["access_token"]')
# 7a 重放：重置密码（与主实例同一新口令，保证两库收敛一致）
code=$(rapi POST "/v1/admin/users/$UID_/password" "$PTOK2" "{\"new_password\":\"$NEW_PW\"}" | tail -1)
assert_eq "$code" 204 "重放重置密码"
code=$(intro "$RBASE" "$T1"); assert_eq "$code" 200 "重施后 introspect HTTP"
python3 -c 'import json;d=json.load(open("/tmp/dr-intro.json"));assert d["active"] is False and d["reason"]=="invalid_or_revoked",d;print("恢复点旧会话重施撤销后仍 invalid_or_revoked")' | tee -a "$EVID"
# 7b 重放：移除平台角色
REV=$(rapi GET "/v1/admin/users/$UID_" "$PTOK2" | sed '$d' | j 'd["auth_revision"]')
code=$(rapi POST "/v1/admin/users/$UID_/platform-roles" "$PTOK2" \
  "{\"role_codes\":[],\"expected_revision\":$REV}" | tail -1)
assert_eq "$code" 200 "重放移除角色"
# 7c 角色限制在恢复实例仍然生效：新会话无权读审计
T2=$(curl -s -X POST "$RBASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$U_ACC\",\"password\":\"$NEW_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}" \
  | j 'd["access_token"]')
code=$(intro "$RBASE" "$T2"); assert_eq "$code" 200 "新会话 introspect"
python3 - <<'PY' | tee -a "$EVID"
import json
d=json.load(open("/tmp/dr-intro.json"))
assert d["active"] is True
assert "platform:audit:read" not in d["permissions"], d["permissions"]
print("角色限制仍生效: 新会话 active 但无 platform:audit:read（权限数=%d）" % len(d["permissions"]))
PY
code=$(curl -s -o /dev/null -w '%{http_code}' "$RBASE/v1/admin/audit-logs" -H "Authorization: Bearer $T2")
assert_eq "$code" 403 "移除角色后审计接口 403"
# 7d 陈旧修订重放必须 409（幂等收敛，不回退）
code=$(rapi POST "/v1/admin/users/$UID_/platform-roles" "$PTOK2" \
  '{"role_codes":["platform_auditor"],"expected_revision":1}' | tail -1)
assert_eq "$code" 409 "陈旧修订重放 409"
log "撤销重施完成：恢复前撤销的会话不复活、角色限制有效、陈旧修订 409 不回退"

log "--- 8. 主实例存活确认"
log "主实例 healthz: $(curl -s "$BASE/healthz")"

log ""
if [ "$fail" -eq 0 ]; then
  log "结果：PASS（备份可恢复；撤销重施后旧会话不复活、角色限制生效；仅操作自有库与 scratch）"
  log "边界声明：本演练只覆盖新项目自有 iam 库，不代表旧 Python 业务库拆库迁移演练（C24 归 I4）。"
else
  log "结果：FAIL"
fi
exit $fail
