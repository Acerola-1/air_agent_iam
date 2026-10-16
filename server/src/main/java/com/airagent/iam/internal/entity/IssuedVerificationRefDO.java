package com.airagent.iam.internal.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * 新登记执行引用的返回行（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.internal.mapper.IdentityMapper#createReference}
 * 经 {@code iam_auth.create_verification_ref(...)} 以 {@code RETURNING id, valid_until} 给出，
 * 服务层据此装配 {@link com.airagent.iam.internal.vo.ExecutionContextVO}。
 *
 * <p>时效语义：{@code valid_until} 由数据库取
 * {@code LEAST(now() + TTL, 原会话 absolute_expires_at)}——引用 TTL（配置
 * {@code iam.internal.verification-ref-ttl-seconds}，默认 43200 秒即 12 小时）只决定引用可被
 * 复查的上界，<b>绝不能用它延长身份本身的有效期</b>。原会话绝对上界更早时以会话为准。
 * 函数在会话不存在或已非 {@code active} 时以 SQLSTATE 28000 报错，由错误翻译落为 401。
 *
 * @param id         新生成的引用 id（{@code gen_random_uuid()}），对外以 UUID 文本回给客户端
 * @param validUntil 引用失效时刻（数据库 timestamptz）；超过该时刻 {@code find_verification_ref} 不再返回该行
 * @author Acerola
 */
public record IssuedVerificationRefDO(UUID id, OffsetDateTime validUntil) {
}
