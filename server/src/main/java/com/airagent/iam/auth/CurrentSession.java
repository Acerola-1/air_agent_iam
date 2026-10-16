package com.airagent.iam.auth;

import java.util.UUID;

/**
 * 请求作用域内已通过"Redis Sa-Token 存活 + PG 主库权威快照"双重核验的会话快照（auth 域共享模型）。
 *
 * <p>由 {@link com.airagent.iam.auth.service.SessionService} 从
 * {@link AuthoritySnapshot} 装配（见 {@code SessionServiceImpl} 的 {@code toCurrent}），
 * 再由 {@link com.airagent.iam.web.BearerAuthInterceptor} 写入请求属性
 * {@code BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE}，或由
 * {@code requireCurrentBySessionId} 在浏览器 {@code /web-api} 链路装配。
 * Controller/Service 各层以它为唯一可信 actor 来源：字段全部取快照值，
 * 不做二次推导，也不携带任何口令或原始令牌。
 *
 * <p>快照只在单次请求内有效：授权代次、企业上下文随时可能在下一个请求被 PG 判定失效，
 * 因此不得跨请求缓存本对象用于放行。
 *
 * @param sessionId       会话 id（iam.auth_sessions.id），撤销/续期/切企业定位的目标
 * @param userId          会话主体用户 id（iam.users.id）
 * @param realm           账号域，当前人类会话恒为 {@code workforce}
 * @param loginAudience   登录时登记的受众（{@code air-agent} / {@code knowledge} / {@code iam-admin}）；
 *                        SSO 兑换出的子会话为其兑换目标受众
 * @param currentTenantId 当前企业 id；{@code null} 表示尚未选择企业（平台域会话）
 * @param ctxVersion      会话上下文代次（auth_sessions.ctx_version），切企业/续期的 CAS 基线；
 *                        首次登录为 1，每次成功切企业 +1
 * @param snapshot        同一请求内加载的原始权威快照，权限码/角色/修订等细粒度判断由它提供
 * @author Acerola
 */
public record CurrentSession(
        UUID sessionId,
        UUID userId,
        String realm,
        String loginAudience,
        UUID currentTenantId,
        long ctxVersion,
        AuthoritySnapshot snapshot
) {
}
