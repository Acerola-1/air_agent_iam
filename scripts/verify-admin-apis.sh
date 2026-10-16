#!/usr/bin/env bash
# 第5组黑盒证据：平台用户/企业/成员/部门/角色权限/审计/服务账号停用（可复跑）。
# A 段：AdminApiIntegrationTest(8) 真实 PG iam_test + Redis。
# B 段：对自管 jar 实例做真实 HTTP 黑盒（平台超管 Bearer + 企业管理员登录切企业）：
#   B1 用户建档/弱口令 400/重复 409/搜索/资料 CAS（仅改资料不推进 auth_revision）
#      /重置密码即时撤会话 401/旧口令 401/最后超管保护 409
#   B2 企业建档 201 revision=1/陈旧修订 409/停用
#   B3 成员：新建 201/同名不合并 409/显式 user_id 关联 201/再关联 409/角色 CAS/停用即时 403/越权 403
#   B4 部门：父子建档/成环 409
#   B5 角色：企业自定义角色 201/平台码越可授边界 409/内置角色保护 403/可授树无平台组无资源码
#   B6 审计：平台可见 NULL 租户/企业只见本租户/分页游标/页宽钳制 200/坏游标 400
#   B7 服务账号：列表/详情无明文/停用即时 introspect inactive/恢复 active
#   B8 秘密扫描：引导口令/SA 明文在证据文件与服务日志零命中
# 用法：./scripts/verify-admin-apis.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
set -a
. ./.env.local
set +a

BASE="http://127.0.0.1:${IAM_HTTP_PORT:-19100}"
CONTAINER_BIN=/usr/local/bin/container
EVIDENCE_DIR="docs/reviews/evidence/group5"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE="$EVIDENCE_DIR/admin-apis.txt"
SERVER_LOG="/tmp/iam-verify-admin-server.log"
TMPDIR_RUN="$(mktemp -d)"

exec > >(tee "$EVIDENCE") 2>&1

section() { printf '\n========== %s ==========\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
sha256hex() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }
basic_auth() { printf 'Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
# curl 封装：req <METHOD> <out文件> <url> <token|null> [json体]
req() {
  local method="$1" out="$2" url="$3" token="$4" body="${5:-}"
  local args=(-s -o "$out" -w '%{http_code}' -X "$method" "$url")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  curl "${args[@]}"
}
jget() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2" 2>/dev/null || true; }

section "环境与前置"
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'java: %s\n' "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-pg17' || fail "iam-pg17 未运行"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-redis7' || fail "iam-redis7 未运行"

SUFFIX="$(date +%H%M%S)$((RANDOM%1000))"
ADM_ACC="b5adm-$SUFFIX"; ADM_PW="Adm-Pass-$SUFFIX-0123"
U1_ACC="b5user1-$SUFFIX"; U2_ACC="b5user2-$SUFFIX"; EXT_ACC="b5ext-$SUFFIX"
M1_ACC="b5m1-$SUFFIX"; M1_PW="Member-Pass-$SUFFIX-0123"
STRONG_PW="ResetPass-$SUFFIX-789"
TENANT_ID="$(uuidgen | tr 'A-Z' 'a-z')"; TENANT_CODE="B5-$SUFFIX"; TENANT_NAME="五组验证企业"
TENANT2_CODE="B5T2-$SUFFIX"
MEMBERSHIP_ID="$(uuidgen | tr 'A-Z' 'a-z')"
KNOW_CLIENT="b5know-$SUFFIX"; KNOW_SECRET="b5know-secret-$SUFFIX-0123456789abcdef"
SA_ACC="sa-b5-$SUFFIX"

SERVER_PID=""; CLEANUP_STARTED=0
if curl -sf -o /dev/null "$BASE/healthz"; then
  printf '复用已在 %s 运行的服务\n' "$BASE"
else
  section "构建并启动本脚本自管服务实例"
  ( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw -q -DskipTests package )
  "$JAVA_HOME/bin/java" -jar server/target/iam-server.jar > "$SERVER_LOG" 2>&1 &
  SERVER_PID=$!; CLEANUP_STARTED=1
  for _ in $(seq 1 60); do sleep 1; curl -sf -o /dev/null "$BASE/healthz" && break; done
fi
curl -s "$BASE/healthz"; echo

cleanup() {
  if [ "$CLEANUP_STARTED" = "1" ] && [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$TMPDIR_RUN"
}
trap cleanup EXIT

section "A 段：AdminApiIntegrationTest(8)，真实 PG iam_test/Redis"
( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw test -Dtest='AdminApiIntegrationTest' )

section "B0：平台登录 + 首位企业管理员种子（成员关系由 migrate 角色单事务植入）"
code=$(curl -s -o "$TMPDIR_RUN/login.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/login.json"; fail "平台登录期望 200，实际 $code"; }
PTOKEN=$(jget "$TMPDIR_RUN/login.json" access_token); [ -n "$PTOKEN" ] || fail "未取到平台令牌"

code=$(req POST "$TMPDIR_RUN/adm.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"$ADM_ACC\",\"display_name\":\"五组企业管理员\",\"password\":\"$ADM_PW\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/adm.json"; fail "管理员建档期望 201，实际 $code"; }
ADM_ID=$(jget "$TMPDIR_RUN/adm.json" id)
code=$(req POST "$TMPDIR_RUN/ext.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"$EXT_ACC\",\"display_name\":\"平台已有账号\",\"password\":\"$STRONG_PW\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/ext.json"; fail "外部账号建档期望 201，实际 $code"; }
EXT_ID=$(jget "$TMPDIR_RUN/ext.json" id)

# knowledge 受众内部客户端（供 SA introspection）
"$CONTAINER_BIN" exec -i iam-pg17 psql -U iam_migrate -d iam -v ON_ERROR_STOP=1 <<SQL
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences)
VALUES ('$KNOW_CLIENT','$KNOW_CLIENT','$(sha256hex "$KNOW_SECRET")',
        ARRAY['identity:introspect']::text[], ARRAY['knowledge']::text[])
ON CONFLICT (client_id) DO NOTHING;
INSERT INTO iam.tenants(id, code, name, created_by)
VALUES ('$TENANT_ID','$TENANT_CODE','$TENANT_NAME','$ADM_ID'::uuid);
SELECT iam_auth.set_request_context('$ADM_ID'::uuid,'$TENANT_ID'::uuid,false);
INSERT INTO iam.tenant_memberships(id, tenant_id, user_id, created_by)
VALUES ('$MEMBERSHIP_ID','$TENANT_ID','$ADM_ID'::uuid,'$ADM_ID'::uuid);
INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by)
SELECT '$TENANT_ID','$MEMBERSHIP_ID', r.id, '$ADM_ID'::uuid
  FROM iam.roles r WHERE r.scope='tenant' AND r.code='tenant_admin';
COMMIT;
SQL

# 企业管理员登录并切企业
code=$(curl -s -o "$TMPDIR_RUN/alogin.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$ADM_ACC\",\"password\":\"$ADM_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/alogin.json"; fail "企业管理员登录期望 200，实际 $code"; }
ATOKEN_RAW=$(jget "$TMPDIR_RUN/alogin.json" access_token)
code=$(req POST "$TMPDIR_RUN/aswitch.json" "$BASE/v1/auth/switch-tenant" "$ATOKEN_RAW" \
  "{\"tenant_id\":\"$TENANT_ID\",\"expected_ctx_version\":1}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/aswitch.json"; fail "切企业期望 200，实际 $code"; }
# switch-tenant 返回新会话令牌（无令牌轮换时也可沿用原令牌；兼容两种实现）
ATOKEN=$(jget "$TMPDIR_RUN/aswitch.json" access_token); [ -n "$ATOKEN" ] || ATOKEN="$ATOKEN_RAW"
echo "首位企业管理员就绪 tenant=$TENANT_CODE admin=$ADM_ACC"

section "B1：用户建档/弱口令/重复/搜索/资料 CAS/重置密码即时撤销/最后超管保护"
code=$(req POST "$TMPDIR_RUN/u1.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"$U1_ACC\",\"display_name\":\"五组用户1\",\"password\":\"$STRONG_PW\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/u1.json"; fail "用户建档期望 201，实际 $code"; }
U1_ID=$(jget "$TMPDIR_RUN/u1.json" id)
python3 - "$TMPDIR_RUN/u1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["auth_revision"]==0, d
blob=json.dumps(d,ensure_ascii=False)
assert "password" not in blob.lower() and "hash" not in blob.lower(), blob
print("建档 201 id=%s auth_revision=0 响应无口令字段" % d["id"][:13])
PY
code=$(req POST "$TMPDIR_RUN/weak.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"b5weak-$SUFFIX\",\"display_name\":\"弱口令\",\"password\":\"123\"}")
[ "$code" = "400" ] || fail "弱口令期望 400，实际 $code"
python3 -c 'import json;print("弱口令 400:",json.load(open("'$TMPDIR_RUN'/weak.json"))["error"]["message"])'
code=$(req POST "$TMPDIR_RUN/dup.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"$U1_ACC\",\"display_name\":\"重复\",\"password\":\"$STRONG_PW\"}")
[ "$code" = "409" ] || fail "重复账号期望 409，实际 $code"
echo "重复账号 409 ok"
code=$(req GET "$TMPDIR_RUN/u1get.json" "$BASE/v1/admin/users/$U1_ID" "$PTOKEN")
[ "$code" = "200" ] || fail "用户详情期望 200，实际 $code"
code=$(curl -s -o "$TMPDIR_RUN/search.json" -w '%{http_code}' \
  "$BASE/v1/admin/users?q=$U1_ACC&limit=10" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || fail "用户搜索期望 200，实际 $code"
python3 - "$TMPDIR_RUN/search.json" "$U1_ACC" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); acc=sys.argv[2]
assert any(i["account"]==acc for i in d["items"]), d
print("搜索命中 %d 条，含目标账号" % len(d["items"]))
PY
code=$(req PATCH "$TMPDIR_RUN/u1stale.json" "$BASE/v1/admin/users/$U1_ID" "$PTOKEN" \
  "{\"display_name\":\"陈旧修订\",\"expected_revision\":99}")
[ "$code" = "409" ] || fail "陈旧资料修订期望 409，实际 $code"
code=$(req PATCH "$TMPDIR_RUN/u1ok.json" "$BASE/v1/admin/users/$U1_ID" "$PTOKEN" \
  "{\"display_name\":\"五组用户1改名\",\"expected_revision\":0}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/u1ok.json"; fail "资料更新期望 200，实际 $code"; }
python3 - "$TMPDIR_RUN/u1ok.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["auth_revision"]==0 and d["display_name"]=="五组用户1改名", d
print("资料 CAS 成功且不推进 auth_revision（仍 0）")
PY
# 重置密码即时撤销
code=$(req POST "$TMPDIR_RUN/u2.json" "$BASE/v1/admin/users" "$PTOKEN" \
  "{\"account\":\"$U2_ACC\",\"display_name\":\"五组用户2\",\"password\":\"$STRONG_PW\"}")
[ "$code" = "201" ] || fail "用户2建档期望 201，实际 $code"
U2_ID=$(jget "$TMPDIR_RUN/u2.json" id)
code=$(curl -s -o "$TMPDIR_RUN/u2login.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$U2_ACC\",\"password\":\"$STRONG_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || fail "用户2登录期望 200，实际 $code"
U2_TOKEN=$(jget "$TMPDIR_RUN/u2login.json" access_token)
code=$(req GET /dev/null "$BASE/v1/auth/me" "$U2_TOKEN"); [ "$code" = "200" ] || fail "重置前 /me 期望 200，实际 $code"
code=$(req POST "$TMPDIR_RUN/reset.json" "$BASE/v1/admin/users/$U2_ID/password" "$PTOKEN" \
  "{\"new_password\":\"Changed-$SUFFIX-99\",\"expected_revision\":0}")
[ "$code" = "204" ] || { cat "$TMPDIR_RUN/reset.json"; fail "重置密码期望 204，实际 $code"; }
code=$(req GET "$TMPDIR_RUN/meold.json" "$BASE/v1/auth/me" "$U2_TOKEN")
[ "$code" = "401" ] || fail "重置后旧会话期望 401，实际 $code"
echo "旧会话即时撤销 401 ok"
code=$(curl -s -o "$TMPDIR_RUN/oldpw.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$U2_ACC\",\"password\":\"$STRONG_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "401" ] || fail "旧口令登录期望 401，实际 $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$U2_ACC\",\"password\":\"Changed-$SUFFIX-99\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || fail "新口令登录期望 200，实际 $code"
echo "旧口令 401 / 新口令 200 ok"
# 最后超管保护：取引导账号 id 与真实修订，撤空平台角色
code=$(curl -s -o "$TMPDIR_RUN/bootq.json" -w '%{http_code}' \
  "$BASE/v1/admin/users?q=$IAM_BOOTSTRAP_ACCOUNT" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || fail "查引导账号期望 200，实际 $code"
python3 - "$TMPDIR_RUN/bootq.json" "$IAM_BOOTSTRAP_ACCOUNT" > "$TMPDIR_RUN/boot.idrev" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
m=[i for i in d["items"] if i["account"]==sys.argv[2]]
assert m, d
print(m[0]["id"], m[0]["auth_revision"])
PY
read -r BOOT_ID BOOT_REV < "$TMPDIR_RUN/boot.idrev"
code=$(req POST "$TMPDIR_RUN/lastadmin.json" "$BASE/v1/admin/users/$BOOT_ID/platform-roles" "$PTOKEN" \
  "{\"role_codes\":[],\"expected_revision\":$BOOT_REV}")
[ "$code" = "409" ] || { cat "$TMPDIR_RUN/lastadmin.json"; fail "撤空最后超管期望 409，实际 $code"; }
echo "最后平台超管保护 409 ok"

section "B2：企业建档/修订/停用"
code=$(req POST "$TMPDIR_RUN/t2.json" "$BASE/v1/admin/tenants" "$PTOKEN" \
  "{\"code\":\"$TENANT2_CODE\",\"name\":\"五组第二企业\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/t2.json"; fail "企业建档期望 201，实际 $code"; }
T2_ID=$(jget "$TMPDIR_RUN/t2.json" id)
python3 - "$TMPDIR_RUN/t2.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert d["auth_revision"]==1, d
print("企业建档 201 revision=1: %s" % d["code"])
PY
code=$(req PATCH "$TMPDIR_RUN/t2stale.json" "$BASE/v1/admin/tenants/$T2_ID" "$PTOKEN" \
  '{"status":"suspended","expected_revision":99}')
[ "$code" = "409" ] || fail "企业陈旧修订期望 409，实际 $code"
code=$(req PATCH "$TMPDIR_RUN/t2ok.json" "$BASE/v1/admin/tenants/$T2_ID" "$PTOKEN" \
  '{"status":"suspended","expected_revision":1}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/t2ok.json"; fail "企业停用期望 200，实际 $code"; }
echo "企业停用 CAS ok；企业管理员写企业接口必须 403"
code=$(req POST "$TMPDIR_RUN/tcross.json" "$BASE/v1/admin/tenants" "$ATOKEN" \
  "{\"code\":\"B5X-$SUFFIX\",\"name\":\"越权建企\"}")
[ "$code" = "403" ] || fail "企业管理员建档企业期望 403，实际 $code"

section "B3：成员建档/不自动合并/显式关联/角色 CAS/停用即时失效/平台接口越权"
code=$(req POST "$TMPDIR_RUN/m1.json" "$BASE/v1/admin/members" "$ATOKEN" \
  "{\"tenant_id\":\"$TENANT_ID\",\"account\":\"$M1_ACC\",\"display_name\":\"五组成员\",\"password\":\"$M1_PW\",\"role_codes\":[\"tenant_reader\"]}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/m1.json"; fail "成员建档期望 201，实际 $code"; }
M1_MEM=$(python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/m1.json"));print(d["id"])')
python3 - "$TMPDIR_RUN/m1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["revision"]==2 and d["roles"]==["tenant_reader"], d
print("成员建档 201 membership revision=2（建档带角色触发器已推进）")
PY
# 同名不合并：不带 user_id 再建必须 409（即便口令也给了，查重先于口令校验）
code=$(req POST "$TMPDIR_RUN/mdup.json" "$BASE/v1/admin/members" "$ATOKEN" \
  "{\"tenant_id\":\"$TENANT_ID\",\"account\":\"$M1_ACC\",\"display_name\":\"重复成员\",\"password\":\"$STRONG_PW\"}")
[ "$code" = "409" ] || fail "同名成员不自动合并期望 409，实际 $code"
# 显式 user_id 关联既有全局账号 201，再次关联 409
code=$(req POST "$TMPDIR_RUN/mext.json" "$BASE/v1/admin/members" "$ATOKEN" \
  "{\"tenant_id\":\"$TENANT_ID\",\"user_id\":\"$EXT_ID\",\"role_codes\":[\"tenant_reader\"]}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/mext.json"; fail "显式关联既有账号期望 201，实际 $code"; }
EXT_MEM=$(python3 -c 'import json;print(json.load(open("'$TMPDIR_RUN'/mext.json"))["id"])')
code=$(req POST "$TMPDIR_RUN/mext2.json" "$BASE/v1/admin/members" "$ATOKEN" \
  "{\"tenant_id\":\"$TENANT_ID\",\"user_id\":\"$EXT_ID\",\"role_codes\":[\"tenant_reader\"]}")
[ "$code" = "409" ] || fail "重复关联期望 409，实际 $code"
echo "同名不合并 409 / 显式 user_id 201 / 重复关联 409 ok"
# 角色替换 CAS：陈旧 409，正确修订 2 → 触发器 DELETE+INSERT 推进到 4
code=$(req POST "$TMPDIR_RUN/rstale.json" "$BASE/v1/admin/members/$M1_MEM/roles" "$ATOKEN" \
  '{"role_codes":["tenant_reader"],"expected_revision":99}')
[ "$code" = "409" ] || fail "成员角色陈旧修订期望 409，实际 $code"
code=$(req POST "$TMPDIR_RUN/rok.json" "$BASE/v1/admin/members/$M1_MEM/roles" "$ATOKEN" \
  '{"role_codes":["tenant_reader"],"expected_revision":2}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/rok.json"; fail "成员角色替换期望 200，实际 $code"; }
NEW_REV=$(jget "$TMPDIR_RUN/rok.json" revision)
[ "$NEW_REV" = "4" ] || fail "角色替换后期望 revision=4，实际 $NEW_REV"
echo "角色全量替换 CAS ok，revision=4"
# 停用即时生效：成员先登录切企业 /me 200，停用后 403
code=$(curl -s -o "$TMPDIR_RUN/mlogin.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"account\":\"$M1_ACC\",\"password\":\"$M1_PW\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
[ "$code" = "200" ] || fail "成员登录期望 200，实际 $code"
MTOKEN_RAW=$(jget "$TMPDIR_RUN/mlogin.json" access_token)
code=$(curl -s -o "$TMPDIR_RUN/mswitch.json" -w '%{http_code}' -X POST "$BASE/v1/auth/switch-tenant" \
  -H "Authorization: Bearer $MTOKEN_RAW" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"expected_ctx_version\":1}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/mswitch.json"; fail "成员切企业期望 200，实际 $code"; }
MTOKEN=$(jget "$TMPDIR_RUN/mswitch.json" access_token); [ -n "$MTOKEN" ] || MTOKEN="$MTOKEN_RAW"
code=$(req GET /dev/null "$BASE/v1/auth/me" "$MTOKEN"); [ "$code" = "200" ] || fail "成员停用前 /me 期望 200，实际 $code"
code=$(req PATCH "$TMPDIR_RUN/mdisable.json" "$BASE/v1/admin/members/$M1_MEM" "$ATOKEN" \
  '{"status":"disabled","expected_revision":4}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/mdisable.json"; fail "停用成员期望 200，实际 $code"; }
code=$(req GET "$TMPDIR_RUN/mego.json" "$BASE/v1/auth/me" "$MTOKEN")
[ "$code" = "403" ] || fail "停用成员实时核验期望 403，实际 $code"
echo "成员停用即时生效 403 ok"
# 企业令牌访问平台用户接口必须 403
code=$(req GET /dev/null "$BASE/v1/admin/users" "$ATOKEN")
[ "$code" = "403" ] || fail "企业管理员访问平台用户接口期望 403，实际 $code"
echo "平台/企业可授分离 403 ok"

section "B4：部门树建档与成环拒绝"
code=$(req POST "$TMPDIR_RUN/d1.json" "$BASE/v1/admin/departments?tenant_id=$TENANT_ID" "$ATOKEN" \
  "{\"code\":\"D1-$SUFFIX\",\"name\":\"一级部门\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/d1.json"; fail "部门 d1 建档期望 201，实际 $code"; }
D1_ID=$(jget "$TMPDIR_RUN/d1.json" id)
code=$(req POST "$TMPDIR_RUN/d2.json" "$BASE/v1/admin/departments?tenant_id=$TENANT_ID" "$ATOKEN" \
  "{\"code\":\"D2-$SUFFIX\",\"name\":\"二级部门\",\"parent_id\":\"$D1_ID\"}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/d2.json"; fail "部门 d2 建档期望 201，实际 $code"; }
D2_ID=$(jget "$TMPDIR_RUN/d2.json" id)
code=$(req PATCH "$TMPDIR_RUN/cycle.json" "$BASE/v1/admin/departments/$D1_ID" "$ATOKEN" \
  "{\"parent_id\":\"$D2_ID\"}")
[ "$code" = "409" ] || { cat "$TMPDIR_RUN/cycle.json"; fail "部门成环期望 409，实际 $code"; }
echo "层级成环 409 ok"

section "B5：企业角色可授边界/内置角色保护/可授树"
code=$(req POST "$TMPDIR_RUN/r1.json" "$BASE/v1/admin/roles" "$ATOKEN" \
  "{\"scope\":\"tenant\",\"code\":\"b5role_$SUFFIX\",\"name\":\"五组自定义角色\",\"permission_codes\":[\"tenant:member:read\"]}")
[ "$code" = "201" ] || { cat "$TMPDIR_RUN/r1.json"; fail "企业自定义角色期望 201，实际 $code"; }
CUSTOM_RID=$(jget "$TMPDIR_RUN/r1.json" id)
code=$(req POST "$TMPDIR_RUN/rbad.json" "$BASE/v1/admin/roles" "$ATOKEN" \
  "{\"scope\":\"tenant\",\"code\":\"b5bad_$SUFFIX\",\"name\":\"越权角色\",\"permission_codes\":[\"platform:user:read\"]}")
[ "$code" = "409" ] || fail "企业角色挂平台权限期望 409，实际 $code"
echo "可授边界：tenant 角色授 platform 码 409 ok"
# 内置企业角色不可改
code=$(curl -s -o "$TMPDIR_RUN/roles.json" -w '%{http_code}' \
  "$BASE/v1/admin/roles?scope=tenant" -H "Authorization: Bearer $ATOKEN")
[ "$code" = "200" ] || fail "角色列表期望 200，实际 $code"
BUILTIN_RID=$(python3 - "$TMPDIR_RUN/roles.json" <<'PY'
import json,sys
for r in json.load(open(sys.argv[1]))["items"]:
    if r["code"]=="tenant_admin": print(r["id"]); break
PY
)
code=$(req PATCH "$TMPDIR_RUN/rbuilt.json" "$BASE/v1/admin/roles/$BUILTIN_RID" "$ATOKEN" \
  '{"name":"篡改内置角色"}')
[ "$code" = "403" ] || fail "改内置角色期望 403，实际 $code"
echo "内置角色保护 403 ok"
# 可授树：企业上下文不见平台组、不见资源型权限
code=$(req GET "$TMPDIR_RUN/tree.json" "$BASE/v1/admin/grantable-tree" "$ATOKEN")
[ "$code" = "200" ] || fail "可授树期望 200，实际 $code"
python3 - "$TMPDIR_RUN/tree.json" <<'PY'
import json,sys
tree=json.load(open(sys.argv[1]))
blob=json.dumps(tree,ensure_ascii=False)
assert "platform:" not in blob, "企业可授树不得出现平台权限"
assert "knowledge:" not in blob, "I1 资源型权限必须从可授树缺席"
print("可授树分组:", [(g["scope"], len(g["permissions"])) for g in tree["groups"]])
PY
code=$(req GET "$TMPDIR_RUN/perms.json" "$BASE/v1/admin/permissions" "$ATOKEN")
[ "$code" = "200" ] || fail "权限目录期望 200，实际 $code"
python3 - "$TMPDIR_RUN/perms.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
codes=[p["code"] for p in d["items"]]
assert any(c.startswith("tenant:") for c in codes) and not any(c.startswith("platform:") for c in codes), codes
assert not any("knowledge:" in c for c in codes), "资源型权限不得进目录"
print("权限目录 %d 条，仅企业可授，无资源型" % len(codes))
PY

section "B6：审计日志隔离/分页/页宽钳制/坏游标"
code=$(curl -s -o "$TMPDIR_RUN/auditp.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?limit=5" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/auditp.json"; fail "平台审计期望 200，实际 $code"; }
python3 - "$TMPDIR_RUN/auditp.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert len(d["items"]) <= 5, d
print("平台审计首页页宽生效，本页 %d 条" % len(d["items"]))
PY
# 满页覆盖本轮事件：平台视角必须同时含 NULL 租户（平台级）事件与本租户事件
code=$(curl -s -o "$TMPDIR_RUN/auditpall.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?limit=200" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || fail "平台审计满页期望 200，实际 $code"
python3 - "$TMPDIR_RUN/auditpall.json" "$TENANT_ID" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); tid=sys.argv[2]
tids={i.get("tenant_id") for i in d["items"]}
assert None in tids, "平台视角应含 NULL 租户（平台级）事件: %r" % tids
assert tid in tids, "平台视角应含本租户事件"
print("平台审计跨租户可见：NULL 平台级事件 + 租户事件共存，共 %d 条" % len(d["items"]))
PY
code=$(curl -s -o "$TMPDIR_RUN/audita.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?limit=200" -H "Authorization: Bearer $ATOKEN")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/audita.json"; fail "企业审计期望 200，实际 $code"; }
python3 - "$TMPDIR_RUN/audita.json" "$TENANT_ID" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); tid=sys.argv[2]
assert d["items"], "本轮企业事件不应为空"
assert all(i.get("tenant_id")==tid for i in d["items"]), "企业视角混入其他租户/NULL 事件"
print("企业审计 %d 条全部属于本租户（RLS 强制，无 NULL/跨租户泄漏）" % len(d["items"]))
PY
# 页宽硬上界：limit>200 一律 400（契约参数 maximum=200，绝不返回超宽页）
code=$(curl -s -o "$TMPDIR_RUN/auditwide.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?limit=999" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "400" ] || { cat "$TMPDIR_RUN/auditwide.json"; fail "limit=999 期望 400 硬拒绝，实际 $code"; }
python3 -c 'import json;print("页宽上界拒绝:",json.load(open("'$TMPDIR_RUN'/auditwide.json"))["error"]["message"])'
code=$(curl -s -o "$TMPDIR_RUN/audit200.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?limit=200" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || fail "limit=200 边界期望 200，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/audit200.json"));assert len(d["items"])<=200;print("limit=200 边界放行，实际 %d 条（分页恒 ≤200）" % len(d["items"]))'
code=$(curl -s -o "$TMPDIR_RUN/badcursor.json" -w '%{http_code}' \
  "$BASE/v1/admin/audit-logs?cursor=%21%21bad" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "400" ] || fail "坏游标期望 400，实际 $code"
echo "坏游标 400 ok"

section "B7：服务账号列表/详情无明文/停用即时/恢复"
code=$(req POST "$TMPDIR_RUN/sa.json" "$BASE/v1/admin/service-accounts" "$PTOKEN" \
  "{\"account\":\"$SA_ACC\",\"name\":\"五组服务账号\",\"tenant_id\":\"$TENANT_ID\",\"audiences\":[\"knowledge\"],\"expires_in_days\":90,\"permissions\":[\"tenant:member:read\"]}")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/sa.json"; fail "SA 建档期望 200，实际 $code"; }
SA_ID=$(jget "$TMPDIR_RUN/sa.json" id)
code=$(curl -s -o "$TMPDIR_RUN/salist.json" -w '%{http_code}' \
  "$BASE/v1/admin/service-accounts?tenant_id=$TENANT_ID" -H "Authorization: Bearer $PTOKEN")
[ "$code" = "200" ] || fail "SA 列表期望 200，实际 $code"
code=$(req GET "$TMPDIR_RUN/sadet0.json" "$BASE/v1/admin/service-accounts/$SA_ID" "$PTOKEN")
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/sadet0.json"; fail "SA 详情期望 200，实际 $code"; }
code=$(req POST "$TMPDIR_RUN/satok.json" "$BASE/v1/admin/service-accounts/$SA_ID/tokens" "$PTOKEN" \
  '{"overlap_hours":0}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/satok.json"; fail "SA 令牌签发期望 200，实际 $code"; }
SA_SECRET=$(jget "$TMPDIR_RUN/satok.json" secret)
code=$(req GET "$TMPDIR_RUN/sadet.json" "$BASE/v1/admin/service-accounts/$SA_ID" "$PTOKEN")
[ "$code" = "200" ] || fail "SA 详情(含令牌)期望 200，实际 $code"
python3 - "$TMPDIR_RUN/salist.json" "$TMPDIR_RUN/sadet.json" "$SA_ACC" <<'PY'
import json,sys
lst,det,acc=sys.argv[1],sys.argv[2],sys.argv[3]
l=json.load(open(lst)); d=json.load(open(det))
assert any(i["account"]==acc for i in l["items"]), l
for blob in (json.dumps(l),json.dumps(d)):
    low=blob.lower()
    assert "secret" not in low, "列表/详情不得含令牌明文"
    assert "token_digest" not in low, "不得返回令牌摘要"
t=d["tokens"][0]
assert set(["credential_id","credential_revision","status"]).issubset(t) and "secret" not in t, t
print("列表/详情仅凭据元数据：credential_id=%s status=%s" % (t["credential_id"][:12],t["status"]))
PY
intro() {
  curl -s -o "$TMPDIR_RUN/saintro.json" -w '%{http_code}' -X POST "$BASE/v1/internal/identity/introspect" \
    -H "Authorization: $(basic_auth "$KNOW_CLIENT" "$KNOW_SECRET")" -H 'Content-Type: application/json' \
    -d "{\"subject_token\":\"$SA_SECRET\",\"audience\":\"knowledge\"}"
}
code=$(intro); [ "$code" = "200" ] || { cat "$TMPDIR_RUN/saintro.json"; fail "SA introspect 期望 200，实际 $code"; }
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/saintro.json"));assert d["active"] is True;print("停用前 introspect active")'
code=$(req PATCH "$TMPDIR_RUN/sadis.json" "$BASE/v1/admin/service-accounts/$SA_ID" "$PTOKEN" \
  '{"status":"disabled"}')
[ "$code" = "200" ] || { cat "$TMPDIR_RUN/sadis.json"; fail "SA 停用期望 200，实际 $code"; }
code=$(intro); [ "$code" = "200" ] || fail "停用后 introspect HTTP 期望 200，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/saintro.json"));assert d["active"] is False,d;print("停用后 introspect 即时 inactive:",d.get("reason"))'
code=$(req PATCH "$TMPDIR_RUN/saen.json" "$BASE/v1/admin/service-accounts/$SA_ID" "$PTOKEN" \
  '{"status":"active"}')
[ "$code" = "200" ] || fail "SA 恢复期望 200，实际 $code"
code=$(intro); [ "$code" = "200" ] || fail "恢复后 introspect HTTP 期望 200，实际 $code"
python3 -c 'import json;d=json.load(open("'$TMPDIR_RUN'/saintro.json"));assert d["active"] is True;print("恢复后 introspect active")'

section "B8：秘密扫描（证据文件 + 服务日志）"
# 证据由本脚本自身写出：引导口令与 SA 明文绝不落盘
for needle_name in IAM_BOOTSTRAP_PASSWORD ADM_PW M1_PW SA_SECRET; do
  needle="${!needle_name}"
  if grep -Fq -- "$needle" "$EVIDENCE" 2>/dev/null; then fail "证据文件出现 $needle_name 明文"; fi
done
if [ "$CLEANUP_STARTED" = "1" ]; then
  for needle_name in IAM_BOOTSTRAP_PASSWORD SA_SECRET; do
    needle="${!needle_name}"
    if grep -Fq -- "$needle" "$SERVER_LOG" 2>/dev/null; then fail "服务日志出现 $needle_name 明文"; fi
  done
  echo "服务日志秘密扫描零命中"
else
  echo "复用外部服务实例，跳过服务日志扫描（仅扫描证据文件，零命中）"
fi

section "结论：全部黑盒断言通过"
date -u +%Y-%m-%dT%H:%M:%SZ
echo "证据：$EVIDENCE"
