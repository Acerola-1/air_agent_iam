#!/usr/bin/env bash
# 已退役：旧在线验收入口；原主体仅保留为历史参考。
printf '%s\n' '已退役：禁止在正式环境运行旧在线验收；现行入口和隔离测试见 README.md。' >&2
exit 2

# 7.1 I1 首期验收矩阵 C01–C17：真实 HTTP + PG + Redis，逐脚本正反证据汇总。
# 不接入两 Python 仓库（只读约束）；合成消费者/合成 A-B 企业由各脚本自管夹具。
# 产物：docs/reviews/evidence/group7/matrix/matrix-<UTC时间戳>.txt 与各脚本原始日志。
set -u
cd "$(dirname "$0")/.."
: "${IAM_HTTP_PORT:=19100}"
OUT="docs/reviews/evidence/group7/matrix"
mkdir -p "$OUT"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$OUT/matrix-$TS.txt"

run() {
  local id="$1" name="$2" cmd="$3"
  local sf="$OUT/$id-$TS.log"
  echo ">>> [$id] $name" | tee -a "$LOG"
  bash -c "$cmd" >"$sf" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "    PASS  $id  ($name) log=$sf" | tee -a "$LOG"
  else
    echo "    FAIL  $id rc=$rc ($name) log=$sf" | tee -a "$LOG"
  fi
  return $rc
}

{
  echo "I1 首期验收矩阵（C01–C17/C25–C30 证据映射）"
  echo "时间(UTC): $TS"
  echo "服务: http://127.0.0.1:${IAM_HTTP_PORT}  healthz: $(curl -s "http://127.0.0.1:${IAM_HTTP_PORT}/healthz" || echo DOWN)"
  echo "Java: ${JAVA_HOME:-未设置 JAVA_HOME（脚本内 mvnw 可能用系统默认）}"
  echo
} >"$LOG"

fails=0
run G0 "C01 环境形状/回环/构建启动" "scripts/verify-gate0-env.sh" || fails=$((fails+1))
run CRYPTO "C02/C03 bcrypt 与 rt-v1 跨语言固定向量" "scripts/verify-crypto-vectors.sh" || fails=$((fails+1))
run CONTRACT "C04/C12 OpenAPI3.1 与协议消费者正反样本" "scripts/verify-contract.sh" || fails=$((fails+1))
run DB "C04/C08/C09/C10/C16 受限 PG 角色隔离/约束/无环" "scripts/verify-db-isolation.sh" || fails=$((fails+1))
run SESSION "C05/C06/C07/C11/C16 会话权威/CAS/故障窗口/续期" "scripts/verify-session-authority.sh" || fails=$((fails+1))
run INTERNAL "C12/C13/C15 内部客户端/服务账号/verification_ref/限流" "scripts/verify-internal-principals.sh" || fails=$((fails+1))
run ADMIN "C08/C09/C26 管理 API 建档/授权/审计/最后管理员" "scripts/verify-admin-apis.sh" || fails=$((fails+1))
run WEB "C17/C27/C28 浏览器会话/SSO 合成双客户端/同源静态" "scripts/verify-web-session.sh" || fails=$((fails+1))

cat >>"$LOG" <<EOF

C-ID -> 证据映射（自动段）
  C01  G0 + docs/reviews/evidence/gate0/c01-build-start.txt
  C02  CRYPTO + group1/c02-c03-crypto-vectors.txt + group4/c02-c03-cross-language-vectors.txt
  C03  CRYPTO + INTERNAL（rt-v1 Java/Python 双向验签 B3）
  C04  CONTRACT + DB + SESSION（登录/多企业/空企业/平台角色）
  C05  SESSION B1-B3（logout/改密/停用后旧会话立即拒绝）
  C06  SESSION A 段（成员停用/角色移除，A 受影响 B 不污染）
  C07  SESSION A 段（切企业 CAS：并发恰一胜 + A→B→A 旧页拒绝）
  C08  DB + ADMIN（跨租户 FK/部门无环/最后管理员）
  C09  DB + ADMIN（平台专属权限企业不可授/可授树）
  C10  DB（非 owner GUC 行策略/连接池清理）
  C11  SESSION（503 失败关闭/授权与审计同事务/outbox 重放）+ group6/dependency-failure-503.txt
  C12  CONTRACT + INTERNAL（非法 JSON/字段/aud/inactive 语义）
  C13  INTERNAL（内部客户端错凭据/错受众/引用不可独立鉴权）
  C15  INTERNAL（服务账号分型/轮换/撤销/资源型默认拒绝）
  C16  DB + SESSION（续期边界/过期不可复活/不回退期限）
  C17  WEB（host-only/HttpOnly/SameSite、错回调/ticket 重放/CSRF）
人工/浏览器证据段（非本脚本）
  C25  group7/perf-introspection.txt（7.2 性能/并发/故障）
  C26  group6/browser-evidence.md（真实浏览器建档/改密/审计；企业内页面待夹具）
  C27  WEB SPA 段（生产同源深链/缺失资源 JSON 404）
  C28  WEB + group6/browser-evidence.md（JS 无 Bearer/无 Node BFF）
  C29  web 单测 14/14；真实双企业 A→B→A 待 seed-browser-fixture 授权
  C30  group6/narrow-*.png/json + browser-evidence.md（390×844/键盘/冲突提示）
范围外（I1a/I2/I3/I4，不计入通过）：C14/C18/C19/C20/C21/C22/C23/C24

结果：$((8-fails))/8 段通过，fails=$fails
EOF

echo
echo "矩阵写入 $LOG"
[ "$fails" -eq 0 ]
