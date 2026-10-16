package com.airagent.iam.auth.entity;

import java.util.UUID;

/**
 * 会话身份定位行（DO，仅 {@link com.airagent.iam.auth.mapper.SessionMapper#findContext} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.find_session_by_digest(token_digest)}：
 * auth_sessions 受 RLS 保护（{@code user_id = app.user_id OR platform}），在无请求上下文时
 * 只能经该函数按令牌摘要反查会话主体与当前企业。
 *
 * <p>注意与权威快照的区别：本行不携带状态、时限与授权代次，不能用于放行判断，
 * 仅用于"摘要 → 主体/租户"的最小映射。
 *
 * @param userId          会话主体用户 id（auth_sessions.user_id）
 * @param currentTenantId 会话当前企业 id；{@code null} 表示尚未选择企业
 * @author Acerola
 */
public record SessionContextDO(UUID userId, UUID currentTenantId) {
}
