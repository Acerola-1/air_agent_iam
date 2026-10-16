#!/usr/bin/env bash
# C04/C08/C09/C10/C16：真实受限 PG 角色 iam_app 对 iam_test 的隔离/约束/反例集成测试（可复跑）。
# 前置：./scripts/infra-up.sh 已起自有容器；iam_test 库与 iam_migrate/iam_app 角色已存在。
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
set -a
. ./.env.local
set +a
( cd server && ./mvnw test -Dtest=DbIsolationIntegrationTest )
