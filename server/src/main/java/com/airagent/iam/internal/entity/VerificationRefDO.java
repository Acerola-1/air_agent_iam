package com.airagent.iam.internal.entity;

import java.util.UUID;

/**
 * {@code iam.verification_refs} 单行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.internal.mapper.IdentityMapper#findReference}
 * 经 {@code iam_auth.find_verification_ref(id, client_id, audience)} 返回，函数已在
 * {@code WHERE} 中筛掉客户端不匹配、受众不匹配与 {@code valid_until <= now()} 的引用，
 * 因此本视图出现即代表"引用自身仍有效"，主体是否仍然可用需由服务层另读权威快照判定。
 *
 * <p>访问边界：{@code iam.verification_refs} 启用了 RLS 且未对请求角色
 * {@code iam_app} 开放任何策略，读写只能经 {@code SECURITY DEFINER} 函数进入。
 * 引用行不保存令牌摘要、不保存任何密钥材料，只有会话标识与修订快照——
 * 引用不是授权票据，不具备 Bearer 能力。
 *
 * @param sessionId     原会话 id（{@code iam.auth_sessions.id} 外键）；复查据此回读同一权威快照路径
 * @param userId        引用登记时的主体用户 id；仅作登记事实，实时判定仍以快照为准
 * @param tenantId      引用登记时的企业 id，可为 {@code null}（平台域上下文，登录但未选企业）
 * @param revisionsJson 登记时刻四项修订的 jsonb 原文（键为 SNAKE_CASE：user_auth_revision 等），
 *                      服务层解析后与请求基线、当前实时值做三方全等比较；解析失败按依赖故障处理
 * @author Acerola
 */
public record VerificationRefDO(UUID sessionId, UUID userId, UUID tenantId, String revisionsJson) {
}
