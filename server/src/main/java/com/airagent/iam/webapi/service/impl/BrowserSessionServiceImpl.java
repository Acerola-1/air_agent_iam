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
 * 浏览器句柄用例：匿名开户、登录后防固定轮换绑定、解析、续期、吊销。
 * 原始句柄只存在于 HttpOnly cookie；库与 Redis 只出现 sha256 摘要。
 */
@Service
public class BrowserSessionServiceImpl implements BrowserSessionService {

    private final BrowserHandleMapper browserHandleMapper;
    private final IamProperties props;
    private final SessionService sessionService;

    public BrowserSessionServiceImpl(BrowserHandleMapper browserHandleMapper, IamProperties props, SessionService sessionService) {
        this.browserHandleMapper = browserHandleMapper;
        this.props = props;
        this.sessionService = sessionService;
    }

    @Override
    public IssuedHandle openAnonymous() {
        IssuedHandle handle = IssuedHandle.generate(props.web().handleTtlSeconds());
        browserHandleMapper.open(OpaqueTokens.digest(handle.rawHandle()), handle.csrfToken(), handle.expiresAt());
        return handle;
    }

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
     * 登录成功后轮换：旧匿名句柄原子吊销，新句柄绑定真实会话与新 CSRF。
     * 旧句柄缺失（cookie 过期）时以 null 绑定，不影响登录成立。
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

    @Override
    public BrowserHandleRow resolve(String rawHandle) {
        if (rawHandle == null || rawHandle.isBlank()) {
            return null;
        }
        return browserHandleMapper.resolve(OpaqueTokens.digest(rawHandle));
    }

    @Override
    public void touch(BrowserHandleRow row) {
        if (row == null || row.sessionId() == null || row.revokedAt() != null) {
            return;
        }
        browserHandleMapper.touch(row.digest(), OffsetDateTime.now(ZoneOffset.UTC)
                .plusSeconds(props.web().handleTtlSeconds()));
    }

    /** 登出时吊销句柄，返回其绑定的会话 id（调用方已另行权威撤销会话）。 */
    @Override
    public UUID revoke(String rawHandle) {
        if (rawHandle == null || rawHandle.isBlank()) {
            return null;
        }
        return browserHandleMapper.revoke(OpaqueTokens.digest(rawHandle));
    }

}
