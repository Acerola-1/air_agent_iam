package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;

/**
 * 凭据签发结果的列裁剪投影（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.mapper.ServiceAccountMapper#issueToken}
 * 装配，取的是 SECURITY DEFINER 函数 {@code iam_auth.issue_service_token(...)} 以
 * {@code RETURNING} 形式返回的<b>新建</b> iam.service_tokens 行中的三列，其余列（内部主键、
 * {@code credential_id}、{@code rotated_at}、时间戳等）不投影。服务层用它补全
 * {@link com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO}，因为签发时刻的权威值
 * （代次与到期）由数据库决定，不能凭应用侧推算。
 *
 * <p>摘要与明文的存储边界：本投影只承载“元数据”，既不含明文密钥也不含
 * {@code token_digest} 摘要列——摘要仅作为入参单向写入库内，任何结果对象都不会把它读回来。
 * 明文密钥由服务层在调用前生成、只放进一次响应，服务端不留副本。
 *
 * @param credentialRevision 新凭据在所属账号内的代次，由函数以“已有最大值 + 1”计算，
 *                           首次签发为 1
 * @param expiresAt          新凭据的到期时刻（数据库回显传入值），核验时到点即失效
 * @param overlapUntil       新凭据自身的重叠上界。函数插入新行时该列固定写 {@code null}
 *                           （窗口只写在被取代的旧凭据上），故本字段在本投影中恒为
 *                           {@code null}，仅保留以对齐函数返回的列形状
 * @author Acerola
 */
public record IssuedTokenDO(long credentialRevision, OffsetDateTime expiresAt, OffsetDateTime overlapUntil) {
}
