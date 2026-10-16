package com.airagent.iam.webapi.service;

import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.webapi.BrowserHandleRow;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/** 浏览器身份业务接口。 */
public interface BrowserSessionService {
    IssuedHandle openAnonymous();
    IssuedHandle resolveCsrf(String existingHandle);
    IssuedHandle bind(String oldRawHandle, UUID sessionId);
    BrowserHandleRow resolve(String rawHandle);
    void touch(BrowserHandleRow row);
    UUID revoke(String rawHandle);
    /** 新随机句柄与配对 CSRF；TTL 对齐会话空闲上界。 */
    public record IssuedHandle(String rawHandle, String csrfToken, OffsetDateTime expiresAt) {
        public static IssuedHandle generate(long ttlSeconds) {
            return new IssuedHandle(OpaqueTokens.newRawToken(), OpaqueTokens.newRawToken(),
                    OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(ttlSeconds));
        }
    }
}
