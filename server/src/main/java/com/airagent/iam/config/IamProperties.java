package com.airagent.iam.config;

import java.util.List;
import java.util.Map;

/**
 * iam.* 配置（期限/票据/bootstrap/限流/浏览器适配/合成SSO）。
 */
@org.springframework.boot.context.properties.ConfigurationProperties(prefix = "iam")
public record IamProperties(
        String issuer,
        Bootstrap bootstrap,
        Session session,
        Internal internal,
        Rt rt,
        RateLimit rateLimit,
        Web web,
        Sso sso
) {
    public record Bootstrap(String account, String displayName, String password) {
    }

    public record Session(long absoluteTimeoutSeconds, long idleTimeoutSeconds, long renewIdleSeconds) {
    }

    /**
     * @param ticketTtlSeconds          rt-v1 短入口票据 TTL（固定 60）
     * @param verificationRefTtlSeconds verification_ref 引用上界（受会话绝对上界再取小）
     * @param runtimeClient             启动时幂等预置的合成 runtime 内部客户端（秘密仅来自环境）
     */
    public record Internal(long ticketTtlSeconds, long verificationRefTtlSeconds,
                           ClientProvision runtimeClient) {
    }

    public record ClientProvision(String id, String secret) {
    }

    /** rt-v1 当前签名密钥（kid 轮换另立 change；固定向量工具已验证 kid 不匹配拒绝）。 */
    public record Rt(String kid, String secret) {
    }

    public record RateLimit(boolean enabled, long windowSeconds, int loginLimit, int internalLimit) {
    }

    /**
     * 浏览器 /web-api 适配配置。生产（secureCookies=true）使用 __Host- 前缀 cookie；
     * 本机 HTTP 使用独立 dev 名，不伪造 Host 限制。allowedOrigins 为精确白名单，
     * 仅纳入本机 Vite 回环地址，不支持通配。
     */
    public record Web(
            boolean secureCookies,
            String sessionCookieDev,
            String sessionCookieProd,
            String csrfCookieDev,
            String csrfCookieProd,
            long handleTtlSeconds,
            String staticLocations,
            List<String> allowedOrigins,
            String centralBaseUrl,
            boolean syntheticConsumerEnabled
    ) {
    }

    /**
     * 合成 SSO：两个自有回环 BFF 客户端，独立密钥/精确回调/受众；state 与 30 秒一次性 ticket。
     */
    public record Sso(long stateTtlSeconds, long ticketTtlSeconds, Map<String, SsoClient> clients) {
    }

    public record SsoClient(
            String id,
            String name,
            String secret,
            String callbackUrl,
            List<String> origins,
            String audience
    ) {
    }
}
