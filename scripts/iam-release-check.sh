#!/usr/bin/env bash
# 第二阶段 IAM 发布前只读检查：root 显式授权复验 + 旧 Agent MCP 授权清点。
# 只读，不写数据库；证据写入已被 .gitignore 忽略的 docs/reviews/evidence/run/。
#
# 必需：IAM_OPS_ROOT_USER_ID=<现有 root 精确 UUID>
# 可选：IAM_OPS_TENANT_IDS=<UUID,UUID>（缺省为执行时全部 active 企业）
#       IAM_OPS_EXPECTED_ACCOUNT=<账号，默认 root>
#
# 用法：IAM_OPS_ROOT_USER_ID=<UUID> bash scripts/iam-release-check.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ROOT_ID="${IAM_OPS_ROOT_USER_ID:-}"
if [[ -z "$ROOT_ID" ]]; then
  echo "必须设置 IAM_OPS_ROOT_USER_ID（现有 root 的精确 UUID）" >&2
  exit 2
fi
TS="$(date -u +%Y%m%dT%H%M%SZ)"
EVID="$ROOT/docs/reviews/evidence/run"
mkdir -p "$EVID"
ARGS=(--iam.ops.root-user-id="$ROOT_ID")
if [[ -n "${IAM_OPS_EXPECTED_ACCOUNT:-}" ]]; then
  ARGS+=(--iam.ops.expected-account="$IAM_OPS_EXPECTED_ACCOUNT")
fi
if [[ -n "${IAM_OPS_TENANT_IDS:-}" ]]; then
  ARGS+=(--iam.ops.tenant-ids="$IAM_OPS_TENANT_IDS")
fi
bash scripts/iam-ops.sh verify "${ARGS[@]}" \
  --iam.ops.output="$EVID/iam-release-check-$TS-verify.json"
bash scripts/iam-ops.sh inventory \
  --iam.ops.output="$EVID/iam-release-check-$TS-inventory.json"
echo "只读检查完成；证据：$EVID/iam-release-check-$TS-{verify,inventory}.json"
