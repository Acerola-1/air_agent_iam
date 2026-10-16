package com.airagent.iam.webapi;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * browser_handles 单行视图（经 SECURITY DEFINER 读取）。句柄只是"浏览器→会话 id"的
 * 不透明映射，绝不是授权快照；每次请求仍执行 Redis 存活 + PG 权威快照双验。
 */
public record BrowserHandleRow(
        String digest,
        UUID sessionId,
        String csrfToken,
        OffsetDateTime authenticatedAt,
        OffsetDateTime expiresAt,
        OffsetDateTime revokedAt
) {
    public boolean revokedOrExpired() {
        return revokedAt != null || expiresAt == null || !expiresAt.isAfter(OffsetDateTime.now());
    }
}
