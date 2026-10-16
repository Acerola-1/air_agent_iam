package com.airagent.iam.webapi.service;

import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.webapi.BrowserHandleRow;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * 浏览器身份业务接口（Service 层，{@code /web-api} 适配模块唯一对外契约）。
 *
 * <p>分层位置：位于 {@link com.airagent.iam.webapi.controller.WebApiAuthController} /
 * {@link com.airagent.iam.webapi.controller.BrowserCsrfController} 与
 * {@link com.airagent.iam.webapi.BrowserSessionInterceptor} /
 * {@link com.airagent.iam.webapi.CsrfOriginInterceptor} 之下，
 * 由 {@link com.airagent.iam.webapi.mapper.BrowserHandleMapper} 承载数据访问；本接口
 * 只做"句柄生命周期"编排（开户、双提交 CSRF 复用/轮换、登录绑定、解析、滑动 TTL、吊销），
 * <em>不</em>触碰授权快照与令牌摘要——权威核验始终由
 * {@link com.airagent.iam.auth.service.SessionService#requireCurrentBySessionId(UUID)}
 * 完成，句柄只是浏览器 Cookie 与会话 id 之间的不透明映射。
 *
 * <p>安全边界：原始句柄与 CSRF 值只在 {@link IssuedHandle} 中一次性回给调用方，
 * 由 Controller 立即写入 Cookie；库与 Redis 只出现
 * {@link OpaqueTokens#digest(String)} 的 SHA-256 摘要。TTL 对齐
 * {@code iam.web.handle-ttl-seconds}（默认 604800 秒 = 7 天，与
 * {@code iam.session.idle-timeout-seconds} 相同），到期后由 {@code browser_handle_touch}
 * 滑动续期，登录绑定/吊销由数据库函数在同一事务内原子完成。
 *
 * @author Acerola
 */
public interface BrowserSessionService {

    /**
     * 打开新的匿名句柄（{@code session_id = NULL}），落库并返回给调用方下发 Cookie。
     *
     * @return 新生成的 {@link IssuedHandle}，TTL 为 {@code iam.web.handle-ttl-seconds}
     */
    IssuedHandle openAnonymous();

    /**
     * 为 CSRF 端点解析或轮换句柄：登录态复用原句柄，匿名/失效路径重开新句柄。
     *
     * <p>规则：
     * <ul>
     *   <li>入参为空、库中不存在、或已吊销/到期 → 直接开新匿名句柄；</li>
     *   <li>句柄仍活跃且<em>已绑定会话</em>：先用
     *       {@link com.airagent.iam.auth.service.SessionService#requireCurrentBySessionId(UUID)}
     *       核验权威；会话仍有效（例如 {@code iam-admin} 中央会话未撤销）则原样返回同一
     *       {@code rawHandle + csrfToken + expiresAt}，前端可幂等重试；权威判定为 401/403
     *       则吊销旧句柄并开新匿名句柄（"中央退出后旧 Cookie 立即不可用"即在此体现）；
     *       其他异常照常上抛，避免依赖故障伪装成"未登录"；</li>
     *   <li>句柄仍活跃但<em>匿名未绑定会话</em>：吊销旧句柄并开新匿名句柄（每次匿名 CSRF
     *       获取都轮换一次，防止旧随机句柄被长期固定）。</li>
     * </ul>
     *
     * @param existingHandle 请求中携带的原始句柄；{@code null} 或空白视为不存在，直接开新
     * @return 可下发给浏览器的 {@link IssuedHandle}（复用或新开）
     * @throws com.airagent.iam.web.error.ApiException 会话权威核验出现 401/403 之外的错误时透传（
     *                                                例如 503 Redis/PG 依赖故障）
     */
    IssuedHandle resolveCsrf(String existingHandle);

    /**
     * 登录成功后原子绑定：吊销旧匿名句柄 + 写入绑定真实会话与新 CSRF 的句柄。
     *
     * <p>会话固定防护：无论旧句柄是否存在都写新句柄；{@code oldRawHandle} 缺失或空白
     * （Cookie 已过期、首次登录）时以 {@code null} 摘要传入数据库，绑定仍成功、不影响登录成立。
     * 新句柄的 CSRF 令牌会随之重新生成，与旧匿名句柄绑定的 CSRF 完全无关联。
     *
     * @param oldRawHandle 登录前浏览器携带的匿名句柄原始值；可为 {@code null}
     * @param sessionId    刚建立的 {@code iam.auth_sessions.id}
     * @return 新生成的 {@link IssuedHandle}（原始句柄只在返回值出现一次，之后仅存摘要）
     */
    IssuedHandle bind(String oldRawHandle, UUID sessionId);

    /**
     * 读取句柄行（不校验会话权威；权威核验由调用方走
     * {@link com.airagent.iam.auth.service.SessionService#requireCurrentBySessionId(UUID)}）。
     *
     * @param rawHandle 浏览器 Cookie 中的原始句柄；{@code null} 或空白视为未登录
     * @return 命中返回 {@link BrowserHandleRow}（可能是已吊销或已过期的行，由调用方按
     *         {@link BrowserHandleRow#revokedOrExpired()} 判定）；句柄不存在时返回 {@code null}
     */
    BrowserHandleRow resolve(String rawHandle);

    /**
     * 滑动 TTL：仅在句柄仍活跃（未吊销）且已绑定会话时更新到期时刻。
     *
     * <p>匿名句柄<em>不</em>做续期——只有登录后的活跃会话才被 {@code /web-api} 拦截器
     * 每次请求 {@code touch} 一次；这与权威会话的空闲计时口径一致。
     *
     * @param row 已 {@link #resolve} 读回的句柄行；{@code null}、匿名（{@code sessionId} 为空）
     *            或已吊销时静默不更新
     */
    void touch(BrowserHandleRow row);

    /**
     * 主动吊销句柄（登出、匿名轮换等场景）。
     *
     * @param rawHandle 浏览器 Cookie 中的原始句柄；{@code null} 或空白视为无需吊销
     * @return 被吊销句柄绑定的会话 id；已吊销/不存在或匿名句柄返回 {@code null}，
     *         因此本方法天然幂等。权威会话撤销仍由调用方另行完成
     */
    UUID revoke(String rawHandle);

    /**
     * 新随机句柄与配对 CSRF 的一次性出口（Service 内部值对象）。
     *
     * <p>原始句柄与 CSRF 只在此对象中出现一次：Controller 立即写入 Cookie 后不再持有；
     * 数据库仅存其 SHA-256 摘要。{@code expiresAt} 使用 UTC 时刻，与
     * {@code iam.web.handle-ttl-seconds} 严格对齐（默认 604800 秒）。
     *
     * @param rawHandle 32 字节 SecureRandom 经 URL-safe Base64（无填充）编码出的原始句柄；
     *                  只出现在响应 Cookie 中，不进入日志/审计
     * @param csrfToken 与句柄同批生成的双提交 CSRF 值；同时写入 HttpOnly 之外的
     *                  JS 可读 Cookie，权威值另存于 {@code iam.browser_handles.csrf_token}
     * @param expiresAt 句柄到期时刻（{@code now + ttlSeconds}，UTC）；
     *                  Cookie {@code Max-Age} 与之同步
     * @author Acerola
     */
    public record IssuedHandle(String rawHandle, String csrfToken, OffsetDateTime expiresAt) {
        /**
         * 生成新的原始句柄与 CSRF，并给出到期时刻。
         *
         * @param ttlSeconds 句柄 TTL，单位秒；由调用方传入 {@code iam.web.handle-ttl-seconds}
         *                   （默认 604800，即 7 天）
         * @return 全新的 {@link IssuedHandle}
         */
        public static IssuedHandle generate(long ttlSeconds) {
            return new IssuedHandle(OpaqueTokens.newRawToken(), OpaqueTokens.newRawToken(),
                    OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(ttlSeconds));
        }
    }
}
