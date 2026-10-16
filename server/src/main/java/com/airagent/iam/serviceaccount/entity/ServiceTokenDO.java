package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;

/**
 * 服务凭据元数据行（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.mapper.ServiceAccountMapper#selectTokens}
 * 装配，来源是 SECURITY DEFINER 函数 {@code iam_auth.list_service_tokens(uuid)} 的返回表，
 * 而非直读 iam.service_tokens——该表对请求角色 iam_app 只启用 RLS 而没有放行策略，
 * 默认拒绝直读，凭据一律经受控函数读取。服务层再转成
 * {@link com.airagent.iam.serviceaccount.vo.ServiceTokenVO}。
 *
 * <p>摘要与明文的存储边界：iam.service_tokens 的 {@code token_digest} 列保存的是明文密钥的
 * SHA-256 十六进制摘要（见 {@link com.airagent.iam.security.token.OpaqueTokens#digest}），
 * 明文密钥本身<b>从不落库</b>；本投影也不含 {@code token_digest}，函数返回的列里就没有它，
 * 因此详情接口无法导出任何可用于核验的凭据材料。同样不投影内部主键 {@code id} 与
 * V19 引入的 {@code rotated_at}。
 *
 * <p>场景：一个账号可有多行（每次签发一行）。轮换时旧行被写入重叠窗口或立即吊销，
 * 因此列表里同时存在 active 与 revoked 历史行。
 *
 * @param credentialId       对外凭据标识（{@code sak_} + 32 位小写十六进制，全库唯一），
 *                           可安全展示，不是秘密
 * @param credentialRevision 该账号内的凭据代次，从 1 起按已有最大值 +1，签发新凭据即推进；
 *                           与账号级 revision 相互独立
 * @param status             凭据状态，仅 {@code active} / {@code revoked}；
 *                           revoked 行由 {@code revokedAt} 记录吊销时刻
 * @param issuedAt           签发时刻（timestamptz，数据库默认值）
 * @param expiresAt          到期时刻；核验时当前时刻到达或越过该时刻即判无效
 * @param overlapUntil       轮换重叠上界：只写在被本次轮换取代的旧凭据上，取值上限为
 *                           “轮换时刻 + 窗口”与“本凭据 expiresAt”中的较小者；到点即判无效。
 *                           新签发的凭据该列恒为 {@code null}，故本字段可为 {@code null}
 * @param revokedAt          吊销时刻；未被吊销时为 {@code null}。零窗口轮换会立即写入该列
 * @author Acerola
 */
public record ServiceTokenDO(
        String credentialId,
        long credentialRevision,
        String status,
        OffsetDateTime issuedAt,
        OffsetDateTime expiresAt,
        OffsetDateTime overlapUntil,
        OffsetDateTime revokedAt) {
}
