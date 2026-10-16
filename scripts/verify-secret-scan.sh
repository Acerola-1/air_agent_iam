#!/usr/bin/env bash
# Compare all local environment variants; never execute them or overwrite evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/secret_scan.py "${1:?请提供新的证据文件路径}"
