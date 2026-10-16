package com.airagent.iam.webapi.service.impl;

import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.mapper.BrowserHandleMapper;
import com.airagent.iam.webapi.service.BrowserSessionService.IssuedHandle;
import com.airagent.iam.webapi.service.BrowserSessionService;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * {@link BrowserSessionService} 实现：浏览器句柄全生命周期（匿名开户、登录防固定绑定、
 * 解析、滑动 TTL、吊销）。
 *
 * <p>分层位置：只操作 iam.browser_handles（经
 * {@link BrowserHandleMapper} 落到 SECURITY DEFINER 函数），<em>不</em>访问
 * iam.auth_sessions——权威快照与 Redis Sa-Token 存活性由
 * {@link SessionService#requireCurrentBySessionId(UUID)} 独立完成，本类只在
 * {@link #resolveCsrf(String)} 内以它做二次判断以决定"是否复用现有句柄"。
 *
 * <p>安全边界：原始句柄只在 {@link IssuedHandle} 中一次性返回给 Controller 写 Cookie，
 * 本类内部立即通过 {@link OpaqueTokens#digest(String)} 转 SHA-256 摘要传给 Mapper，
 * 数据库与 Redis 都<em>不</em>出现原始令牌；TTL 一律取
 * {@code iam.web.handleTtlSeconds}（默认 604800 秒 = 7 天）。
 *
 * <p>事务边界：{@link #bind(String, UUID)} 的"吊销旧匿名 + 插入新句柄"两步依赖数据库
 * 函数 {@code iam_auth.browser_handle_bind} 在单次调用内原子完成（V10），Java 侧不
 * 显式开启 Spring 事务；其余方法是单条 SQL。
 *
 * @author Acerola
 */
@Service
public class BrowserSessionServiceImpl implements BrowserSessionService {

    /** 浏览器句柄表数据访问。 */
    private final BrowserHandleMapper browserHandleMapper;
    /** iam.* 配置（Cookie 名/TTL/白名单）。 */
    private final IamProperties props;
    /** 中央会话权威服务。 */
    private final SessionService sessionService;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param browserHandleMapper 浏览器句柄数据访问（SECURITY DEFINER 函数包装）
     * @param props               {@code iam.*} 配置；取 {@code iam.web.handle-ttl-seconds}
     * @param sessionService      会话权威服务；仅在 {@link #resolveCsrf(String)} 内用于
     *                            判定"已绑定会话是否仍可用"，不参与其他路径
     */
    public BrowserSessionServiceImpl(BrowserHandleMapper browserHandleMapper, IamProperties props, SessionService sessionService) {
        this.browserHandleMapper = browserHandleMapper;
        this.props = props;
        this.sessionService = sessionService;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先在内存生成新句柄与 CSRF，再以摘要调用 {@code browser_handle_open}；
     * 匿名句柄 {@code session_id} 固定为 {@code null}。
     */
    @Override
    public IssuedHandle openAnonymous() {
        IssuedHandle handle = IssuedHandle.generate(props.web().handleTtlSeconds());
        browserHandleMapper.open(OpaqueTokens.digest(handle.rawHandle()), handle.csrfToken(), handle.expiresAt());
        return handle;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：权威核验捕获的 {@link ApiException} 只在状态为 401 / 403 时才
     * 视作"会话已失效"进入"吊销旧 + 开新"路径；其他状态（如 503 依赖故障）
     * 直接上抛，避免把基础设施故障伪装成未登录。匿名句柄（{@code sessionId} 为空）
     * 每次调用都会轮换，防止攻击者长期持有同一 CSRF 锚点。
     */
    @Override
    public IssuedHandle resolveCsrf(String existingHandle) {
        BrowserHandleRow existing = resolve(existingHandle);
        if (existing != null && !existing.revokedOrExpired()) {
            if (existing.sessionId() != null) {
                try {
                    sessionService.requireCurrentBySessionId(existing.sessionId());
                    return new IssuedHandle(existingHandle, existing.csrfToken(), existing.expiresAt());
                } catch (ApiException ex) {
                    if (ex.status() != 401 && ex.status() != 403) {
                        throw ex;
                    }
                }
            }
            revoke(existingHandle);
        }
        return openAnonymous();
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：{@code oldRawHandle} 为 {@code null} 或空白时其摘要传 {@code null}，
     * 由 {@code browser_handle_bind} 跳过旧行吊销直接写入新绑定；这覆盖了"首次登录"
     * 与"Cookie 已过期"两种缺旧句柄场景，不影响登录成立。新句柄 {@code authenticated_at}
     * 由数据库函数写 now()。
     */
    @Override
    public IssuedHandle bind(String oldRawHandle, UUID sessionId) {
        IssuedHandle fresh = IssuedHandle.generate(props.web().handleTtlSeconds());
        String oldDigest = oldRawHandle == null || oldRawHandle.isBlank()
                ? null : OpaqueTokens.digest(oldRawHandle);
        browserHandleMapper.bind(oldDigest, OpaqueTokens.digest(fresh.rawHandle()), sessionId,
                fresh.csrfToken(), fresh.expiresAt());
        return fresh;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：{@code null} 与空白一律视为"未携带句柄"，直接短路返回 {@code null}，
     * 不进入 Mapper；非空入参经 SHA-256 摘要后按主键查表。
     */
    @Override
    public BrowserHandleRow resolve(String rawHandle) {
        if (rawHandle == null || rawHandle.isBlank()) {
            return null;
        }
        return browserHandleMapper.resolve(OpaqueTokens.digest(rawHandle));
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：{@code row == null}、匿名（{@code sessionId} 为空）或已吊销的句柄
     * 静默跳过；有效句柄以 {@code now(UTC) + iam.web.handle-ttl-seconds} 更新到期时刻。
     */
    @Override
    public void touch(BrowserHandleRow row) {
        if (row == null || row.sessionId() == null || row.revokedAt() != null) {
            return;
        }
        browserHandleMapper.touch(row.digest(), OffsetDateTime.now(ZoneOffset.UTC)
                .plusSeconds(props.web().handleTtlSeconds()));
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：{@code null} 或空白句柄直接返回 {@code null}；否则按摘要吊销并取回
     * 绑定的会话 id。调用方在 {@link com.airagent.iam.webapi.controller.WebApiAuthController}
     * 里独立调用 {@link SessionService#logout(com.airagent.iam.auth.CurrentSession)}
     * 完成权威撤销——本方法只清理浏览器侧映射。
     */
    @Override
    public UUID revoke(String rawHandle) {
        if (rawHandle == null || rawHandle.isBlank()) {
            return null;
        }
        return browserHandleMapper.revoke(OpaqueTokens.digest(rawHandle));
    }

}
