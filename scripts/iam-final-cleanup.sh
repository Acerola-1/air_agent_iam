#!/usr/bin/env bash
# 第二阶段 IAM 最终清理与复验。仅在 Agent 已切换新模型、旧表/旧接口/旧码请求停止后执行。
#
# 行为（全部可重入，不创建备份）：
#   1. 清点旧 enterprise:mcp / mcp:binding:read / mcp:binding:manage；
#   2. 单一事务删除命中的角色/服务账号关联与权限定义，推进修订并写审计；
#   3. 再次清点应为零项；
#   4. 复验 root 业务授权仍完整。
#
# 必需：IAM_OPS_ROOT_USER_ID=<现有 root 精确 UUID>
# 可选：IAM_OPS_TENANT_IDS=<UUID,UUID>、IAM_OPS_EXPECTED_ACCOUNT=<账号，默认 root>
#
# 用法：IAM_OPS_ROOT_USER_ID=<UUID> bash scripts/iam-final-cleanup.sh --apply
# 未带 --apply 时只打印用法并退出 2，不执行任何写操作。
set -euo pipefail
if [[ "${1:-}" != "--apply" ]]; then
  echo "用法：IAM_OPS_ROOT_USER_ID=<UUID> bash scripts/iam-final-cleanup.sh --apply" >&2
  echo "该命令会物理删除旧 Agent MCP 授权定义及关联；不创建备份或回退。" >&2
  exit 2
fi
shift
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
  --iam.ops.output="$EVID/iam-final-cleanup-$TS-before-verify.json"
bash scripts/iam-ops.sh cleanup-plan \
  --iam.ops.output="$EVID/iam-final-cleanup-$TS-cleanup-plan.json"
bash scripts/iam-ops.sh cleanup-apply \
  --iam.ops.output="$EVID/iam-final-cleanup-$TS-cleanup-apply.json"
bash scripts/iam-ops.sh inventory \
  --iam.ops.output="$EVID/iam-final-cleanup-$TS-inventory-after.json"
bash scripts/iam-ops.sh verify "${ARGS[@]}" \
  --iam.ops.output="$EVID/iam-final-cleanup-$TS-after-verify.json"
echo "最终清理与复验完成；证据：$EVID/iam-final-cleanup-$TS-*.json"
