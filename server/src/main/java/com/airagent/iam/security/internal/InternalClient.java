package com.airagent.iam.security.internal;

import java.util.List;

/**
 * 已认证内部客户端（机器主体，realm=internal_client）。
 * 每次请求经主库 authenticate_internal_client 实时核验，不做凭据缓存。
 */
public record InternalClient(
        String clientId,
        String name,
        List<String> scopes,
        List<String> audiences,
        String status
) {
    public boolean hasScope(String scope) {
        return scopes != null && scopes.contains(scope);
    }

    public boolean hasAudience(String audience) {
        return audiences != null && audiences.contains(audience);
    }
}
