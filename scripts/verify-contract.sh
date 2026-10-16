#!/usr/bin/env bash
# C04/C12 契约冻结验收：OpenAPI 3.1 自校验 + 身份/请求正反样本 + 跨字段语义反例。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec tools/.venv/bin/python contracts/consumer/protocol_consumer_test.py
