#!/usr/bin/env bash
# 以前台方式运行 IAM 服务（JDK21 + .env.local 合成秘密）。日志：server/logs/iam-server.log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
test -f .env.local || { echo "缺少 .env.local"; exit 1; }
set -a; . ./.env.local; set +a
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
JAR="$ROOT/server/target/iam-server.jar"
if [ "${1:-}" = "--build" ] || [ ! -f "$JAR" ]; then
  (cd server && ./mvnw -q -DskipTests package)
fi
mkdir -p server/logs
exec "$JAVA_HOME/bin/java" $JAVA_OPTS -jar "$JAR"
