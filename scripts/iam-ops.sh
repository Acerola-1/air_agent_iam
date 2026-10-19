#!/usr/bin/env bash
# IAM 一次性运维命令入口（非 Web、非启动钩子）。
#
# 用法：
#   bash scripts/iam-ops.sh plan --iam.ops.root-user-id=<UUID> [--iam.ops.tenant-ids=<UUID,UUID>]
#   bash scripts/iam-ops.sh apply --iam.ops.root-user-id=<UUID> --iam.ops.all-active-tenants=true
#   bash scripts/iam-ops.sh verify --iam.ops.root-user-id=<UUID>
#   bash scripts/iam-ops.sh inventory
#   bash scripts/iam-ops.sh cleanup-plan
#   bash scripts/iam-ops.sh cleanup-apply
#
# 可选：--iam.ops.output=<非秘密JSON路径>、--iam.ops.expected-account=<账号，默认root>
# 说明：不创建 dump/快照/影子库/备份表；不修改口令；不启用停用主体。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -f .env.local ]] || { echo "缺少本机 .env.local" >&2; exit 2; }
set -a
. ./.env.local
set +a
# 仅用于隔离测试库的显式覆盖；正式执行不设置该变量。
if [[ -n "${IAM_OPS_PG_DB:-}" ]]; then
  export IAM_PG_DB="$IAM_OPS_PG_DB"
fi

COMMAND="${1:-}"
if [[ -z "$COMMAND" ]]; then
  echo "用法：bash scripts/iam-ops.sh <plan|apply|verify|inventory|cleanup-plan|cleanup-apply> [--iam.ops.*=...]" >&2
  exit 2
fi
shift
export IAM_OPS_COMMAND="$COMMAND"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iam.ops.command=*) export IAM_OPS_COMMAND="${1#*=}" ;;
    --iam.ops.root-user-id=*) export IAM_OPS_ROOT_USER_ID="${1#*=}" ;;
    --iam.ops.expected-account=*) export IAM_OPS_EXPECTED_ACCOUNT="${1#*=}" ;;
    --iam.ops.tenant-ids=*) export IAM_OPS_TENANT_IDS="${1#*=}" ;;
    --iam.ops.all-active-tenants=true) export IAM_OPS_ALL_ACTIVE_TENANTS=true ;;
    --iam.ops.output=*) export IAM_OPS_OUTPUT="${1#*=}" ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

JAR="$ROOT/server/target/iam-server.jar"
if [[ ! -f "$JAR" ]]; then
  (cd server && ./mvnw -q -DskipTests package)
fi
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
  JAVA_BIN="$(command -v java)"
else
  JAVA_BIN="$JAVA_HOME/bin/java"
fi
exec "$JAVA_BIN" -Dloader.main=com.airagent.iam.ops.OpsApplication \
  -cp "$JAR" org.springframework.boot.loader.launch.PropertiesLauncher
