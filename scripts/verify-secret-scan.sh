#!/usr/bin/env bash
# 7.5 秘密零命中扫描：.env.local 的真实秘密值不得出现在任何交付物/证据/日志中。
# 不打印秘密本身；命中时只给文件名与行号。
set -euo pipefail
cd "$(dirname "$0")/.."
: "${1:?用法: bash scripts/verify-secret-scan.sh <输出证据文件>}"
OUT="$1"
mkdir -p "$(dirname "$OUT")"

[ -f .env.local ] || { echo "缺少 .env.local"; exit 1; }
set -a; . ./.env.local; set +a

names=(
  IAM_BOOTSTRAP_PASSWORD
  IAM_PG_MIGRATE_PASSWORD
  IAM_PG_APP_PASSWORD
  IAM_REDIS_PASSWORD
  IAM_CSRF_SECRET
  IAM_RT_KEYS_SECRET
  IAM_SSO_CLIENT_AGENT_SECRET
  IAM_SSO_CLIENT_KB_SECRET
  IAM_INTERNAL_RUNTIME_CLIENT_SECRET
)

# 交付物与证据范围（排除依赖/构建产物/.venv/.env 自身）
DIRS=""
for d in server/src scripts contracts web/src openspec docs tools server/logs; do
  [ -e "$d" ] && DIRS="$DIRS $d"
done
[ -d web/dist ] && DIRS="$DIRS web/dist"

hits=0
: > "$OUT"
{
echo "秘密零命中扫描 $(date -u +%FT%TZ)"
echo "扫描范围:$DIRS"
echo "比对秘密数: ${#names[@]}（值不打印，长度≥12 才视为有效配置）"
} >> "$OUT"

for n in "${names[@]}"; do
  v="${!n:-}"
  [ "${#v}" -ge 12 ] || { echo "SKIP $n（未配置或过短）" >> "$OUT"; continue; }
  if grep -rIlF --exclude-dir='__pycache__' --exclude='*.png' -- "$v" $DIRS 2>/dev/null \
       | sed "s/^/HIT $n: /" >> "$OUT"; then
    hits=$((hits+1))
  fi
done

if [ "$hits" -eq 0 ]; then
  echo "结果：PASS 所有真实秘密在交付物/证据/日志中零命中" >> "$OUT"
else
  echo "结果：FAIL 有 $hits 个秘密出现明文命中（见上）" >> "$OUT"
fi
cat "$OUT"
[ "$hits" -eq 0 ]
