package com.airagent.iam.auth;

import java.util.UUID;

/**
 * 请求作用域内已通过"Redis Sa-Token + PG 权威"双重核验的会话快照。
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
