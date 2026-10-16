#!/usr/bin/env bash
# C02/C03：bcrypt $2b$ 与 rt-v1 跨语言固定向量双向核验（可复跑）。
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-/Users/acerola/Library/Java/JavaVirtualMachines/corretto-21.0.12.1/Contents/Home}"
PY=tools/.venv/bin/python

$PY tools/bcrypt-vectors/bcrypt_vectors.py generate
$PY tools/rt-v1/rt_v1.py generate
( cd server && ./mvnw -q test -Dtest=CrossLanguageVectorTest )
$PY tools/bcrypt-vectors/bcrypt_vectors.py verify-java server/target/bcrypt-java-vectors.json
$PY tools/rt-v1/rt_v1.py verify server/target/rt-v1-java-tokens.json
