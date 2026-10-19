#!/usr/bin/env bash
# 已退役：旧在线验收入口；原主体仅保留为历史参考。
printf '%s\n' '已退役：禁止在正式环境运行旧在线验收；现行入口和隔离测试见 README.md。' >&2
exit 2

# 第6组黑盒证据：浏览器 /web-api 会话适配 + Cookie/CSRF + SSO 合成消费者全链路。
# A 段：BrowserSessionIntegrationTest(9) 真实 PG iam_test + Redis。
# B 段：对自管 jar 实例做真实 HTTP 黑盒（curl 双 cookie jar，模拟浏览器同源请求）：
#   B1 仅回环监听；CSRF 双 cookie 属性；无 Origin/错 Origin/带 Authorization/错 CSRF 写请求一律 403
#   B2 web 登录成功但响应无 access_token/token_type；会话句柄登录后轮换；me/menus 正常
#   B3 /web-api/admin 与 /v1/admin 双挂载同权；未知 API/缺失静态资源保持 JSON 404（不回 HTML）
#   B4 管理员重置成员密码后，旧浏览器会话立即 401（即时撤销）
#   B5 SSO：浏览器发起→中央 start 303→合成 BFF 回调服务端兑换 303→BFF /me 受众隔离；
#      ticket 重放 401、state 重放进回调被拒、错密钥 401、错回调 400；agent/kb 会话互不通用
#   B6 秘密卫生：引导口令、SSO 密钥在证据文件与服务日志零命中
# 用法：./scripts/verify-web-session.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
set -a
. ./.env.local
set +a

BASE="http://127.0.0.1:${IAM_HTTP_PORT:-19100}"
CONTAINER_BIN=/usr/local/bin/container
EVIDENCE_DIR="docs/reviews/evidence/group6"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE="$EVIDENCE_DIR/web-session.txt"
SERVER_LOG="/tmp/iam-verify-web-server.log"
TMPDIR_RUN="$(mktemp -d)"

exec > >(tee "$EVIDENCE") 2>&1

section() { printf '\n========== %s ==========\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
jget() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2" 2>/dev/null || true; }
jpget() { python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d=d[k]
print(d)' "$1" "$2" 2>/dev/null || true; }
basic_auth() { printf 'Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
ck_get() { awk -v n="$2" '$6==n{print $7}' "$1" | tail -1; }
# 同源浏览器风格写请求：wreq <jar> <METHOD> <out> <url> [json体]
wreq() {
  local jar="$1" method="$2" out="$3" url="$4" body="${5:-}"
  local csrf; csrf="$(ck_get "$jar" air_iam_dev_csrf)"
  local args=(-s -o "$out" -w '%{http_code}' -c "$jar" -b "$jar" -X "$method" "$url"
      -H 'Origin: http://127.0.0.1:19100' -H "X-CSRF-Token: $csrf")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}"
}
expect() { [ "$1" = "$2" ] || fail "$3（期望 $2，实际 $1）"; }

section "环境与前置"
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'java: %s\n' "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-pg17' || fail "iam-pg17 未运行"
"$CONTAINER_BIN" list 2>/dev/null | grep -Eq 'iam-redis7' || fail "iam-redis7 未运行"

SUFFIX="$(date +%H%M%S)$((RANDOM%1000))"
WEB_ACC="b6web-$SUFFIX"; WEB_PW="Web-Pass-$SUFFIX-0123"; NEW_PW="Reset-Pass-$SUFFIX-4567"

SERVER_PID=""; CLEANUP_STARTED=0
if curl -sf -o /dev/null "$BASE/healthz"; then
  printf '复用已在 %s 运行的服务\n' "$BASE"
else
  section "构建并启动本脚本自管服务实例"
  ( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw -q -DskipTests package )
  : > "$SERVER_LOG"
  "$JAVA_HOME/bin/java" -jar server/target/iam-server.jar > "$SERVER_LOG" 2>&1 &
  SERVER_PID=$!; CLEANUP_STARTED=1
  for _ in $(seq 1 60); do sleep 1; curl -sf -o /dev/null "$BASE/healthz" && break; done
fi
curl -sf -o /dev/null "$BASE/healthz" || fail "服务未就绪"
curl -s "$BASE/healthz"; echo

cleanup() {
  if [ "$CLEANUP_STARTED" = "1" ] && [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$TMPDIR_RUN"
}
trap cleanup EXIT

section "A 段：BrowserSessionIntegrationTest(9)，真实 PG iam_test/Redis"
( cd server && JAVA_HOME="$JAVA_HOME" ./mvnw -q test -Dtest='BrowserSessionIntegrationTest' )

section "B1：仅回环监听 + CSRF cookie 属性 + 写请求四道闸"
LISTEN_LINE="$(lsof -nP -iTCP:19100 -sTCP:LISTEN 2>/dev/null | tail -1)"
printf '%s\n' "$LISTEN_LINE"
printf '%s' "$LISTEN_LINE" | grep -q '127.0.0.1:19100' || fail "未仅绑定回环地址"
printf '%s' "$LISTEN_LINE" | grep -q '\*:19100' && fail "监听了通配地址" || true

JAR="$TMPDIR_RUN/browser.jar"
curl -s -D "$TMPDIR_RUN/csrf.h" -c "$JAR" "$BASE/web-api/auth/csrf" -o /dev/null
cat "$TMPDIR_RUN/csrf.h" | grep -i '^set-cookie: air_iam_dev_session' | grep -qi 'HttpOnly' || fail "会话 cookie 缺 HttpOnly"
cat "$TMPDIR_RUN/csrf.h" | grep -i '^set-cookie: air_iam_dev_session' | grep -qi 'SameSite=Lax' || fail "会话 cookie 缺 SameSite=Lax"
cat "$TMPDIR_RUN/csrf.h" | grep -i '^set-cookie: air_iam_dev_csrf' | grep -qi 'HttpOnly' && fail "CSRF cookie 不应 HttpOnly（前端需读取）" || true
CSRF_BEFORE="$(ck_get "$JAR" air_iam_dev_csrf)"; HANDLE_BEFORE="$(ck_get "$JAR" air_iam_dev_session)"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/web-api/auth/login" -H 'Content-Type: application/json' -d '{}')
expect "$code" 403 "无 Origin 的登录"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$BASE/web-api/auth/login" -H 'Origin: https://evil.example' -H "X-CSRF-Token: $CSRF_BEFORE" -H 'Content-Type: application/json' -d '{}')
expect "$code" 403 "跨 Origin 的登录"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$BASE/web-api/auth/login" -H 'Origin: http://127.0.0.1:19100' -H "X-CSRF-Token: $CSRF_BEFORE" -H 'Authorization: Bearer abc' -H 'Content-Type: application/json' -d '{}')
expect "$code" 403 "携带 Authorization 的浏览器请求"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$BASE/web-api/auth/login" -H 'Origin: http://127.0.0.1:19100' -H 'X-CSRF-Token: wrong-token' -H 'Content-Type: application/json' -d '{}')
expect "$code" 403 "错误 CSRF token"

section "B2：web 登录成功（响应不出现令牌）+ 句柄轮换 + me/menus"
code=$(curl -s -o "$TMPDIR_RUN/login.json" -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$BASE/web-api/auth/login" \
  -H 'Origin: http://127.0.0.1:19100' -H "X-CSRF-Token: $CSRF_BEFORE" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\"}")
expect "$code" 200 "平台引导账号 web 登录"
grep -q '"audience":"iam-admin"' "$TMPDIR_RUN/login.json" || fail "登录响应受众不是 iam-admin"
grep -q 'access_token' "$TMPDIR_RUN/login.json" && fail "登录响应向浏览器泄露 access_token" || true
grep -q 'token_type' "$TMPDIR_RUN/login.json" && fail "登录响应向浏览器泄露 token_type" || true
HANDLE_AFTER="$(ck_get "$JAR" air_iam_dev_session)"; CSRF_AFTER="$(ck_get "$JAR" air_iam_dev_csrf)"
[ "$HANDLE_AFTER" != "$HANDLE_BEFORE" ] || fail "登录后会话句柄未轮换"
[ -n "$CSRF_AFTER" ] || fail "登录后未下发新 CSRF cookie"
code=$(curl -s -o "$TMPDIR_RUN/me.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/auth/me")
expect "$code" 200 "带句柄访问 me"
[ "$(jget "$TMPDIR_RUN/me.json" audience)" = "iam-admin" ] || fail "me 受众异常"
code=$(curl -s -o "$TMPDIR_RUN/menus.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/auth/menus")
expect "$code" 200 "拉取中文菜单"
grep -q '平台用户' "$TMPDIR_RUN/menus.json" || fail "菜单未按实时权限输出中文项"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/web-api/auth/me")
expect "$code" 401 "无 cookie 访问 me"

section "B2.5：登录后再取 CSRF 不得撤销/降级已登录句柄（页面刷新保真）"
HANDLE_HOLD="$(ck_get "$JAR" air_iam_dev_session)"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" "$BASE/web-api/auth/csrf")
expect "$code" 200 "登录态下 GET csrf"
[ "$(ck_get "$JAR" air_iam_dev_session)" = "$HANDLE_HOLD" ] || fail "GET /csrf 轮换了已登录会话句柄"
code=$(curl -s -o "$TMPDIR_RUN/me2.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/auth/me")
expect "$code" 200 "刷新引导后 me 仍然认证有效"
[ "$(jget "$TMPDIR_RUN/me2.json" audience)" = "iam-admin" ] || fail "刷新后 me 受众异常"

section "B3：/web-api/admin 与 /v1/admin 同权；未知路径保持 JSON 404"
code=$(curl -s -o "$TMPDIR_RUN/web-roles.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/admin/roles")
expect "$code" 200 "web 挂载角色目录"
grep -q 'platform_super_admin' "$TMPDIR_RUN/web-roles.json" || fail "web 角色目录缺少平台超管码"
# Bearer 侧：平台账号走 /v1 登录取令牌
code=$(curl -s -o "$TMPDIR_RUN/v1login.json" -w '%{http_code}' -X POST "$BASE/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$IAM_BOOTSTRAP_ACCOUNT\",\"password\":\"$IAM_BOOTSTRAP_PASSWORD\",\"realm\":\"workforce\",\"audience\":\"iam-admin\"}")
expect "$code" 200 "v1 登录"
PTOKEN="$(jget "$TMPDIR_RUN/v1login.json" access_token)"; [ -n "$PTOKEN" ] || fail "v1 登录未返回令牌"
code=$(curl -s -o "$TMPDIR_RUN/v1-roles.json" -w '%{http_code}' -H "Authorization: Bearer $PTOKEN" "$BASE/v1/admin/roles")
expect "$code" 200 "v1 挂载角色目录"
python3 - "$TMPDIR_RUN/web-roles.json" "$TMPDIR_RUN/v1-roles.json" <<'PY'
import json,sys
a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
def codes(d):
    items = d.get("items", d if isinstance(d, list) else [])
    return sorted(x["code"] for x in items)
if codes(a) != codes(b):
    raise SystemExit("web/v1 角色目录不一致")
print("web/v1 角色目录一致，条目数=%d" % len(codes(a)))
PY
code=$(curl -s -o "$TMPDIR_RUN/miss-api.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/auth/nope")
expect "$code" 404 "未知 web-api 路径"
grep -q '"code"' "$TMPDIR_RUN/miss-api.json" || fail "未知 web-api 未返回 JSON 错误信封"
code=$(curl -s -o "$TMPDIR_RUN/miss-v1.json" -w '%{http_code}' -H "Authorization: Bearer $PTOKEN" "$BASE/v1/admin/nope")
expect "$code" 404 "未知 v1 路径"
code=$(curl -s -o "$TMPDIR_RUN/miss-asset" -w '%{http_code}' "$BASE/assets/index-nope.js")
expect "$code" 404 "缺失的指纹化 JS"
grep -qi '<html' "$TMPDIR_RUN/miss-asset" && fail "缺失 JS 返回了 HTML" || true

section "B4：重置密码即时撤销浏览器会话"
code=$(curl -s -o "$TMPDIR_RUN/newuser.json" -w '%{http_code}' -H "Authorization: Bearer $PTOKEN" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/admin/users" -d "{\"account\":\"$WEB_ACC\",\"display_name\":\"六组浏览器用户\",\"password\":\"$WEB_PW\"}")
expect "$code" 201 "为即时撤销场景建档"
WEB_ID="$(jget "$TMPDIR_RUN/newuser.json" id)"
WJAR="$TMPDIR_RUN/webuser.jar"
curl -s -c "$WJAR" "$BASE/web-api/auth/csrf" -o /dev/null
WCSRF="$(ck_get "$WJAR" air_iam_dev_csrf)"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$WJAR" -b "$WJAR" -X POST "$BASE/web-api/auth/login" \
  -H 'Origin: http://127.0.0.1:19100' -H "X-CSRF-Token: $WCSRF" -H 'Content-Type: application/json' \
  -d "{\"account\":\"$WEB_ACC\",\"password\":\"$WEB_PW\"}")
expect "$code" 200 "被管用户 web 登录"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$WJAR" "$BASE/web-api/auth/me")
expect "$code" 200 "重置前 me 可用"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $PTOKEN" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/admin/users/$WEB_ID/password" -d "{\"new_password\":\"$NEW_PW\"}")
expect "$code" 204 "管理员重置密码"
code=$(curl -s -o "$TMPDIR_RUN/after-reset.json" -w '%{http_code}' -b "$WJAR" "$BASE/web-api/auth/me")
expect "$code" 401 "旧浏览器会话必须即时失效"

section "B5：SSO 合成消费者全链路 + 重放/错密钥/错回调反例 + 受众隔离"
AGENT_ID="${IAM_SSO_CLIENT_AGENT_ID:-air-agent-local}"
KB_ID="${IAM_SSO_CLIENT_KB_ID:-knowledge-local}"
AGENT_CB="http://127.0.0.1:19100/web-api/sso/callback/agent"
KB_CB="http://127.0.0.1:19100/web-api/sso/callback/kb"

# 发起（浏览器持有中央会话）
code=$(curl -s -o /dev/null -w '%{http_code}' -D "$TMPDIR_RUN/agent-start.h" -c "$JAR" -b "$JAR" \
  "$BASE/web-api/sso/callback/agent/login")
expect "$code" 303 "BFF 发起登录"
grep -qi '^set-cookie: air_iam_demo_agent_state' "$TMPDIR_RUN/agent-start.h" || fail "未下发 BFF state cookie"
S0="$(grep -i '^location:' "$TMPDIR_RUN/agent-start.h" | grep -oi 'state=[^&]*$' | head -1 | cut -d= -f2- | tr -d '\r')"
urlenc() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
# 中央 start
code=$(curl -s -o /dev/null -w '%{http_code}' -D "$TMPDIR_RUN/central.h" -c "$JAR" -b "$JAR" \
  "$BASE/web-api/sso/start?client_id=$AGENT_ID&redirect_uri=$(urlenc "$AGENT_CB")&state=$S0")
expect "$code" 303 "中央 SSO start"
CB_LOC="$(grep -i '^location:' "$TMPDIR_RUN/central.h" | sed 's/^[Ll]ocation: //; s/\r$//')"
TICKET="$(printf '%s' "$CB_LOC" | sed -n 's/.*[?&]ticket=\([^&]*\).*/\1/p')"; STATE="$(printf '%s' "$CB_LOC" | sed -n 's/.*[?&]state=\(.*\)/\1/p')"
[ -n "$TICKET" ] && [ -n "$STATE" ] || fail "回调地址缺 ticket/state"
cp "$JAR" "$TMPDIR_RUN/jar-pre-callback"
# BFF 回调（服务端完成兑换）
code=$(curl -s -o /dev/null -w '%{http_code}' -D "$TMPDIR_RUN/callback.h" -c "$JAR" -b "$JAR" "$CB_LOC")
expect "$code" 303 "BFF 回调"
tr -d '\r' < "$TMPDIR_RUN/callback.h" | grep -qi 'location: /demo/agent/?error=$' || fail "回调后未回到演示页或带错误"
grep -qi '^set-cookie: air_iam_demo_agent=' "$TMPDIR_RUN/callback.h" || fail "未下发 BFF 会话 cookie"
grep -qi '^set-cookie: air_iam_demo_agent_state=;' "$TMPDIR_RUN/callback.h" || fail "state cookie 未即时清除"
# BFF 代理 me：受众隔离，浏览器只见身份 JSON
code=$(curl -s -o "$TMPDIR_RUN/bff-me.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/sso/callback/agent/me")
expect "$code" 200 "BFF 代理 me"
[ "$(jget "$TMPDIR_RUN/bff-me.json" audience)" = "air-agent" ] || fail "SSO 会话受众不是 air-agent"
SID_WEB="$(jpget "$TMPDIR_RUN/me.json" 'session.id')"
SID_SSO="$(jpget "$TMPDIR_RUN/bff-me.json" 'session.id')"
[ "$SID_WEB" != "$SID_SSO" ] || fail "SSO 必须签发独立会话而非复用管理会话"
grep -q 'access_token' "$TMPDIR_RUN/bff-me.json" && fail "BFF me 泄露应用令牌" || true

# 反例1：浏览器重放完整回调（state cookie 仍在的快照）
code=$(curl -s -o /dev/null -w '%{http_code}' -D "$TMPDIR_RUN/replay.h" -b "$TMPDIR_RUN/jar-pre-callback" "$CB_LOC")
expect "$code" 303 "重放回调仍应被处理后拒绝"
grep -qi 'location: /demo/agent/?error=\(exchange_rejected\|state_mismatch\)' "$TMPDIR_RUN/replay.h" || { cat "$TMPDIR_RUN/replay.h"; fail "ticket/state 重放未被拒绝"; }
# 反例2：服务端直接兑换已消费 ticket
code=$(curl -s -o "$TMPDIR_RUN/ex-replay.json" -w '%{http_code}' -u "$AGENT_ID:$IAM_SSO_CLIENT_AGENT_SECRET" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/internal/sso/exchange" \
  -d "{\"ticket\":\"$TICKET\",\"state\":\"$STATE\",\"redirect_uri\":\"$AGENT_CB\"}")
expect "$code" 401 "已消费 ticket 重放兑换"
# 反例3：错密钥（先取一枚新 ticket）
mint_ticket() { # $1 client_id $2 callback -> sets TICKET2/STATE2
  local cid="$1" cb="$2" loc
  curl -s -c "$JAR" -b "$JAR" "$BASE/web-api/sso/callback/$3/login" -o /dev/null -D "$TMPDIR_RUN/init.h"
  local st; st="$(grep -i '^location:' "$TMPDIR_RUN/init.h" | grep -oi 'state=[^&]*$' | head -1 | cut -d= -f2- | tr -d '\r')"
  curl -s -c "$JAR" -b "$JAR" "$BASE/web-api/sso/start?client_id=$cid&redirect_uri=$(urlenc "$cb")&state=$st" -o /dev/null -D "$TMPDIR_RUN/central2.h"
  loc="$(grep -i '^location:' "$TMPDIR_RUN/central2.h" | sed 's/^[Ll]ocation: //; s/\r$//')"
  TICKET2="$(printf '%s' "$loc" | sed -n 's/.*[?&]ticket=\([^&]*\).*/\1/p')"
  STATE2="$(printf '%s' "$loc" | sed -n 's/.*[?&]state=\(.*\)/\1/p')"
}
mint_ticket "$AGENT_ID" "$AGENT_CB" agent
code=$(curl -s -o "$TMPDIR_RUN/ex-badsecret.json" -w '%{http_code}' -u "$AGENT_ID:definitely-not-the-secret-0000000000000000" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/internal/sso/exchange" \
  -d "{\"ticket\":\"$TICKET2\",\"state\":\"$STATE2\",\"redirect_uri\":\"$AGENT_CB\"}")
expect "$code" 401 "错密钥兑换"
# 反例4：回调不精确匹配
code=$(curl -s -o "$TMPDIR_RUN/ex-badcb.json" -w '%{http_code}' -u "$AGENT_ID:$IAM_SSO_CLIENT_AGENT_SECRET" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/internal/sso/exchange" \
  -d "{\"ticket\":\"$TICKET2\",\"state\":\"$STATE2\",\"redirect_uri\":\"http://127.0.0.1:19100/web-api/sso/callback/agent/extra\"}")
expect "$code" 400 "篡改 redirect_uri 兑换"
# 反例5：start 阶段回调不精确
code=$(curl -s -o "$TMPDIR_RUN/start-badcb.json" -w '%{http_code}' -b "$JAR" \
  "$BASE/web-api/sso/start?client_id=$AGENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A19100%2Fweb-api%2Fsso%2Fcallback%2Fagent%2Fhijack&state=$STATE2")
expect "$code" 400 "start 阶段篡改回调"
# 受众隔离：agent 的 BFF cookie 不能用于 kb
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/web-api/sso/callback/kb/me")
expect "$code" 401 "agent BFF 会话不得通行 kb"
# kb 完整链路：独立会话、knowledge 受众
mint_and_bind_kb() {
  curl -s -c "$JAR" -b "$JAR" "$BASE/web-api/sso/callback/kb/login" -o /dev/null -D "$TMPDIR_RUN/kbinit.h"
  local st; st="$(grep -i '^location:' "$TMPDIR_RUN/kbinit.h" | grep -oi 'state=[^&]*$' | head -1 | cut -d= -f2- | tr -d '\r')"
  curl -s -c "$JAR" -b "$JAR" "$BASE/web-api/sso/start?client_id=$KB_ID&redirect_uri=$(urlenc "$KB_CB")&state=$st" -o /dev/null -D "$TMPDIR_RUN/kbcentral.h"
  local loc; loc="$(grep -i '^location:' "$TMPDIR_RUN/kbcentral.h" | sed 's/^[Ll]ocation: //; s/\r$//')"
  curl -s -c "$JAR" -b "$JAR" "$loc" -o /dev/null
}
mint_and_bind_kb
code=$(curl -s -o "$TMPDIR_RUN/kb-me.json" -w '%{http_code}' -b "$JAR" "$BASE/web-api/sso/callback/kb/me")
expect "$code" 200 "kb BFF 代理 me"
[ "$(jget "$TMPDIR_RUN/kb-me.json" audience)" = "knowledge" ] || fail "kb SSO 会话受众不是 knowledge"
# 令牌不碰浏览器：整个证据目录不得出现 access_token 字段值（仅允许错误信封/键名检查产生的词）
echo "BFF cookie 清单（浏览器侧可见凭据，仅限不透明句柄）："
awk 'NR>4{print $6}' "$JAR" | sort -u | sed 's/^/  - /'

section "B6：秘密卫生（证据文件 + 服务日志零命中）"
for secret in "$IAM_BOOTSTRAP_PASSWORD" "$IAM_SSO_CLIENT_AGENT_SECRET" "$IAM_SSO_CLIENT_KB_SECRET"; do
  [ -n "$secret" ] || continue
  if grep -qF "$secret" "$EVIDENCE"; then fail "证据文件出现秘密明文"; fi
  if [ -f "$SERVER_LOG" ] && grep -qF "$secret" "$SERVER_LOG"; then fail "服务日志出现秘密明文"; fi
done
echo "引导口令、两个 SSO 密钥在证据与日志零命中"

section "SPA 托管现状（web/dist 构建后应返回 index.html）"
if [ -f web/dist/index.html ]; then
  code=$(curl -s -o "$TMPDIR_RUN/spa.html" -w '%{http_code}' "$BASE/admin/platform/users")
  expect "$code" 200 "SPA 深链直达"
  grep -qi '<!doctype html' "$TMPDIR_RUN/spa.html" || fail "深链未返回 HTML"
  echo "SPA 已构建：深链 /admin/platform/users 200 HTML"
else
  code="$(curl -s -o "$TMPDIR_RUN/spa.json" -w '%{http_code}' "$BASE/admin/platform/users")"
  echo "web/dist 尚未构建：/admin 深链当前 ${code}（JSON 提示），前端组完成后复测 C27"
fi

printf '\n========== 通过：第6组浏览器会话/SSO 证据全部完成 %s ==========\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
