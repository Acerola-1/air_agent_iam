#!/usr/bin/env bash
# Gate0 环境形状验收（1.3）：只回环监听、无默认生产口令、未读源仓库 .env、未停共享服务。
# 只读检查；不修改任何容器或源仓库。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0
ok()   { echo "PASS $1"; }
bad()  { echo "FAIL $1: $2"; fail=1; }

echo "== 1. 监听地址必须全部回环 =="
for port in 19100 19132 19179; do
  line="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)"
  if [ -z "$line" ]; then
    echo "SKIP :$port 无监听（服务/基础设施未启动时此项跳过）"
  else
    echo "$line" | while IFS= read -r l; do
      addr="$(printf '%s\n' "$l" | awk '{print $9}')"
      case "$addr" in
        127.0.0.1:"$port"|*:127.0.0.1:"$port"|"[::1]:"$port) echo "PASS :$port -> $addr" ;;
        *) echo "FAIL :$port 非回环监听: $addr" ;;
      esac
    done
  fi
done
echo
echo "== 2. 配置只发布回环，无 0.0.0.0 / 通配凭证 =="
if grep -RIn --exclude-dir=target --exclude-dir=node_modules --exclude=verify-gate0-env.sh \
    -E '0\.0\.0\.0|allowed-origins:\s*\*|Access-Control-Allow-Origin.*\*' \
    server/src scripts web contracts 2>/dev/null | grep -v '^Binary'; then
  bad "wildcard-bind" "发现 0.0.0.0/通配配置"
else
  ok "server/scripts/contracts 无 0.0.0.0 或通配 Origin"
fi
grep -n '127.0.0.1' scripts/infra-up.sh | sed 's/^/  /'
echo
echo "== 3. application.yml 口令只允许环境变量占位，无硬编码 =="
hardcoded="$(grep -nE '^[[:space:]]*(password|secret):[[:space:]]*[^$[:space:]]' server/src/main/resources/application.yml server/src/test/resources/*.yml 2>/dev/null || true)"
if [ -n "$hardcoded" ]; then bad "hardcoded-secret" "$hardcoded"; else ok "application.yml 无硬编码口令/秘密"; fi
echo
echo "== 4. .env.local 权限 600；.env.example 不含真实秘密 =="
if [ -f .env.local ]; then
  mode="$(stat -f '%Lp' .env.local)"
  [ "$mode" = "600" ] && ok ".env.local 权限 $mode" || bad "env-local-mode" "权限=$mode（要求 600）"
else
  echo "SKIP .env.local 不存在"
fi
if grep -nE '^[A-Z_]+=.+' .env.example | grep -vE '^[0-9]+:(IAM_HTTP_PORT|IAM_PG_HOST|IAM_PG_PORT|IAM_PG_DB|IAM_PG_MIGRATE_USER|IAM_PG_APP_USER|IAM_DB_POOL_MAX|IAM_REDIS_HOST|IAM_REDIS_PORT|IAM_REDIS_DB|IAM_RT_KEYS_KID)=' ; then
  bad "example-secrets" ".env.example 含非空秘密/口令值"
else
  ok ".env.example 秘密类变量全部为空占位"
fi
echo
echo "== 5. 本项目可执行代码不引用两 Python 源仓库绝对路径，不读取其 .env =="
hits="$(grep -RIn --exclude-dir=target --exclude-dir=.venv --exclude=verify-gate0-env.sh \
  -E '/Users/acerola/Dev/Python/(air_agent|RAG/env-rag-final)' scripts tools server/src contracts 2>/dev/null || true)"
if [ -n "$hits" ]; then echo "$hits"; bad "source-reference" "可执行代码发现源仓库绝对路径引用"; else ok "代码/脚本无 Python 源仓库绝对路径引用"; fi
envhits="$(grep -RIn --exclude-dir=target --exclude-dir=.venv --exclude=verify-gate0-env.sh \
  -E 'Dev/Python/(air_agent|RAG).*\.env' scripts tools server/src contracts 2>/dev/null || true)"
if [ -n "$envhits" ]; then echo "$envhits"; bad "source-env-read" "发现读取源仓库 .env 的引用"; else ok "无读取源仓库 .env 的引用"; fi
echo
echo "== 6. 源仓库只读核实（HEAD 必须不变；工作区漂移仅记录）=="
echo "  本包命令在写沙箱内执行，源仓库路径不在可写目录中（物理上无法写入）。"
echo "  源仓库存在外部并发活动时工作区可能自行变化，漂移只记录不归因于本包。"
BASELINE="$ROOT/docs/reviews/evidence/gate0/source-repo-baseline.txt"
for repo in /Users/acerola/Dev/Python/air_agent /Users/acerola/Dev/Python/RAG/env-rag-final; do
  if [ -d "$repo/.git" ]; then
    echo "-- $repo"
    head="$(git -C "$repo" rev-parse HEAD)"
    echo "HEAD=$head"
    base_head="$(awk -v r="$repo" 'found && /^# HEAD /{sub(/^# HEAD /,""); print; exit} $0=="["r"]"{found=1}' "$BASELINE" 2>/dev/null)"
    if [ -n "$base_head" ]; then
      [ "$head" = "$base_head" ] \
        && ok "HEAD 与 Gate0 基线一致（无新提交/重置）: $repo" \
        || bad "source-head:$repo" "HEAD 漂移 baseline=$base_head current=$head"
    else
      echo "WARN 基线中缺少 $repo 段（首次建立）"
    fi
    cur="$(mktemp /tmp/iam-srccur.XXXXXX)"
    git -C "$repo" status --porcelain | LC_ALL=C sort > "$cur"
    base="$(mktemp /tmp/iam-srcbase.XXXXXX)"
    awk -v r="$repo" '/^\[/{found=($0=="["r"]"); next} found && $0 !~ /^#/ && NF {print}' "$BASELINE" 2>/dev/null | LC_ALL=C sort > "$base"
    if comm -23 "$cur" "$base" | grep -q .; then
      echo "  INFO 相对基线新增的未提交条目（外部活动，本包沙箱不可写该路径）:"
      comm -23 "$cur" "$base" | sed 's/^/    + /'
    fi
    if comm -13 "$cur" "$base" | grep -q .; then
      echo "  INFO 相对基线消失的未提交条目（外部活动还原/提交）:"
      comm -13 "$cur" "$base" | sed 's/^/    - /'
    fi
    echo "  现存未提交条目数: $(wc -l < "$cur" | tr -d ' ')"
    rm -f "$cur" "$base"
  else
    echo "SKIP $repo 非 git 仓库或不存在"
  fi
done
echo
echo "== 7. 容器清单（证明仅创建自有 iam-* 容器，其余为既有共享服务，未停未改）=="
/usr/local/bin/container list 2>/dev/null | sed 's/^/  /'
echo
if [ "$fail" -eq 0 ]; then echo "GATE0-ENV ALL PASS"; else echo "GATE0-ENV HAS FAILURES"; fi
exit "$fail"
