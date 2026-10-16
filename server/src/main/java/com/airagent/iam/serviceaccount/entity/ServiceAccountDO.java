package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * iam.service_accounts 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.mapper.ServiceAccountMapper} 的
 * {@code selectById / lockById / selectPage} 装配，服务层再转成
 * {@link com.airagent.iam.serviceaccount.vo.ServiceAccountVO}。
 *
 * <p>场景与协作：服务账号是机器身份的主体，绑定一个企业（{@code tenantId}）并声明可用受众与
 * 有效期。该表为 FORCE RLS，策略只放行“目标企业即上下文企业”或“平台上下文”，本模块统一以
 * 平台上下文读写，故可见全部企业的行。映射列刻意不含 {@code created_by}、{@code created_at}
 * 与 {@code revoked_at}：建档人只作为写入审计列存在，停用时刻由 {@code status} 与审计记录
 * 表达，都不进管理契约。
 *
 * <p>凭据边界：本 DO 不携带任何凭据信息（既无明文密钥也无摘要），凭据是另一张表
 * iam.service_tokens 的行，见 {@link ServiceTokenDO}。
 *
 * @param id        主键，{@code gen_random_uuid()} 生成
 * @param account   服务账号标识，全库唯一，形如 {@code sa-} 前缀的小写标签
 * @param name      显示名，非空
 * @param status    账号状态，数据库 CHECK 允许 {@code active} / {@code disabled} / {@code revoked}；
 *                  本模块只会写入前两种（插入固定 {@code active}，状态接口只接受 active/disabled），
 *                  非 active 时凭据核验返回 account_disabled
 * @param tenantId  所属企业 UUID（iam.tenants.id），签发时要求企业为 active
 * @param audiences 受众码列表（text[]，经 TextArrayTypeHandler 装配）；列可为空数组，
 *                  读取结果恒非 {@code null}，无受众时为空列表
 * @param expiresAt 账号到期时刻（timestamptz，UTC 读取）。建档时受
 *                  {@code service_accounts_expiry_ck} 约束不得晚于写入时刻 +365 天；
 *                  当前时刻到达或越过该时刻即判到期，并拒绝签发新凭据
 * @param revision  账号修订号，插入固定 1；仅状态变更接口每次 +1（同一 SQL 内自增，无条件比较）。
 *                  授予/回收权限、签发/吊销凭据都不推进它
 * @author Acerola
 */
public record ServiceAccountDO(
        UUID id,
        String account,
        String name,
        UUID tenantId,
        String status,
        List<String> audiences,
        OffsetDateTime expiresAt,
        long revision) {
}
