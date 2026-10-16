package com.airagent.iam.webapi;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * iam.browser_handles 单行视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.mapper.BrowserHandleMapper#resolve} 经
 * SECURITY DEFINER 函数 {@code iam_auth.browser_handle_get} 读取（表本身对 iam_app
 * 无直读权限，见 V1 建表与 V10 函数授予），SQL 结果列到 record 组件的映射定义在
 * {@code resources/mapper/webapi/BrowserHandleMapper.xml}。
 *
 * <p>语义边界：句柄只是"浏览器 Cookie → 会话 id"的不透明映射，<em>绝非</em>授权快照——
 * {@code /web-api} 每次请求仍要走 {@link com.airagent.iam.auth.service.SessionService#requireCurrentBySessionId(UUID)}
 * 完成"Redis Sa-Token 存活 + PG 主库权威快照"双检，不引入第二套权威；本行仅给出句柄
 * 有效性、CSRF 绑定值和它所指向的会话 id。原始句柄只存在于 HttpOnly Cookie，
 * 数据库与日志仅出现 {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 得到的 SHA-256 摘要。
 *
 * @param digest          主键 handle_digest，即原始句柄的 SHA-256 十六进制摘要（小写 hex）
 * @param sessionId       绑定的 iam.auth_sessions.id；匿名句柄（尚未登录）为 {@code null}
 * @param csrfToken       与句柄绑定的双提交 CSRF 值，由 {@code OpaqueTokens.newRawToken()} 生成；
 *                        写操作经 X-CSRF-Token 头回传并由服务端常量时间比对
 * @param authenticatedAt 句柄完成登录绑定的时刻（{@code browser_handle_bind} 写 now()）；
 *                        匿名句柄为 {@code null}
 * @param expiresAt       句柄滑动到期时刻；每次成功核验由 {@code browser_handle_touch}
 *                        推至 {@code now + iam.web.handle-ttl-seconds}。理论上列 NOT NULL，
 *                        但 {@link #revokedOrExpired()} 仍按 {@code null} 判失效以防御脏读
 * @param revokedAt       吊销时刻；旧匿名句柄被 {@code browser_handle_bind} 消费或
 *                        {@code browser_handle_revoke} 主动吊销时写入 now()；活跃为 {@code null}
 * @author Acerola
 */
public record BrowserHandleRow(
        String digest,
        UUID sessionId,
        String csrfToken,
        OffsetDateTime authenticatedAt,
        OffsetDateTime expiresAt,
        OffsetDateTime revokedAt
) {
    /**
     * 句柄是否已被吊销或到期。
     *
     * <p>三类失效路径同等对待：{@code revokedAt} 非空、{@code expiresAt} 缺失（防御），
     * 或 {@code expiresAt} 不再严格晚于服务端当前时刻。到期比较基于 {@link OffsetDateTime}
     * 的瞬时点语义，不受数据库返回的偏移量与本机时区差异影响；等号即视为失效。
     *
     * @return 句柄不可再用于放行时为 {@code true}；仍在有效期内且未吊销为 {@code false}
     */
    public boolean revokedOrExpired() {
        return revokedAt != null || expiresAt == null || !expiresAt.isAfter(OffsetDateTime.now());
    }
}
