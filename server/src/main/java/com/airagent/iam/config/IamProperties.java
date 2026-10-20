package com.airagent.iam.config;

import java.util.List;
import java.util.Map;

/**
 * {@code iam.*} 配置绑定（record 树，前缀 iam）。
 *
 * <p>集中承载期限（会话/票据/引用）、首启 bootstrap、限流、浏览器适配与合成 SSO
 * 客户端定义；秘密字段只来自环境变量注入，本类型不持有默认口令。
 * 由 IamApplication 经 {@code @EnableConfigurationProperties} 装配。
 *
 * @param issuer     签发者标识，写入 rt-v1 票据与身份视图
 * @param bootstrap  空库首次启动的管理员预置配置
 * @param session    会话 idle/absolute 时限（秒）
 * @param internal   内部端点票据与核验引用参数
 * @param rt         rt-v1 当前签名密钥（kid + secret）
 * @param rateLimit  登录与内部端点固定窗口限流参数
 * @param web        浏览器会话 Cookie / CSRF / 静态资源适配
 * @param sso        合成 SSO 客户端注册表与 state/ticket 时限
 * @author Acerola
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
    /**
     * 首启管理员预置（仅当目标账号不存在时幂等生效）。
     *
     * @param account      登录账号；留空则跳过预置
     * @param displayName  显示名，缺省"平台超级管理员"
     * @param password     明文口令，仅用于生成 BCrypt 摘要；留空则跳过
     */
    public record Bootstrap(String account, String displayName, String password) {
    }

    /**
     * 会话时限，单位秒。
     *
     * @param absoluteTimeoutSeconds 绝对上限，续期不可越过
     * @param idleTimeoutSeconds     空闲时限，超过未活动即失效
     * @param renewIdleSeconds       单次续期把空闲到期推进到的时长
     */
    public record Session(long absoluteTimeoutSeconds, long idleTimeoutSeconds, long renewIdleSeconds) {
    }

    /**
     * 内部端点票据与核验引用参数。
     *
     * @param ticketTtlSeconds              rt-v1 短入口票据 TTL（固定 60）
     * @param verificationRefTtlSeconds     verification_ref 引用上界（受会话绝对上界再取小）
     * @param runtimeClient                 启动时幂等预置的合成 runtime 内部客户端（秘密仅来自环境）
     * @param knowledgeDelegationTtlSeconds 知识只读委托 TTL（1..60 秒）
     * @param knowledgeConsumerClients      获准消费知识委托内省的内部客户端 client_id 列表
     */
    public record Internal(long ticketTtlSeconds, long verificationRefTtlSeconds,
                           ClientProvision runtimeClient,
                           long knowledgeDelegationTtlSeconds,
                           List<String> knowledgeConsumerClients) {
    }

    /**
     * 待幂等预置的内部客户端凭据形状。
     *
     * @param id     客户端标识（clientId）
     * @param secret 客户端明文密钥；预置时转摘要存储，每次启动实为密钥轮换
     */
    public record ClientProvision(String id, String secret) {
    }

    /**
     * rt-v1 当前签名密钥（kid 轮换另立 change；固定向量工具已验证 kid 不匹配拒绝）。
     *
     * @param kid    密钥标识，写入票据信封第一段
     * @param secret HMAC 密钥原文；留空则签票端点返回 503
     */
    public record Rt(String kid, String secret) {
    }

    /**
     * 固定窗口限流参数（RateLimiter 消费）。
     *
     * @param enabled       总开关；关闭仅用于隔离压力采样，默认开启
     * @param windowSeconds 窗口长度（秒）
     * @param loginLimit    每窗口登录尝试上限（按来源）
     * @param internalLimit 每窗口内部端点调用上限（按客户端）
     */
    public record RateLimit(boolean enabled, long windowSeconds, int loginLimit, int internalLimit) {
    }

    /**
     * 浏览器 /web-api 适配配置。生产（secureCookies=true）使用 __Host- 前缀 cookie；
     * 本机 HTTP 使用独立 dev 名，不伪造 Host 限制。allowedOrigins 为精确白名单，
     * 仅纳入本机 Vite 回环地址，不支持通配。
     *
     * @param secureCookies               是否按 HTTPS 语义下发 Secure/__Host- cookie（本机默认 false）
     * @param sessionCookieDev            开发态会话 Cookie 名
     * @param sessionCookieProd           生产态会话 Cookie 名（__Host- 前缀）
     * @param csrfCookieDev               开发态 CSRF Cookie 名
     * @param csrfCookieProd              生产态 CSRF Cookie 名（__Host- 前缀）
     * @param handleTtlSeconds            匿名浏览器句柄有效期（秒），与会话空闲时限对齐
     * @param staticLocations             SPA 静态资源位置列表文本（Spring 资源解析格式）
     * @param allowedOrigins              CSRF Origin 精确白名单（scheme://host:port）
     * @param centralBaseUrl              中央授权页基址（SSO start 重定向用）
     * @param syntheticConsumerEnabled    是否启用合成消费者 BFF 演示端点
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
     *
     * @param stateTtlSeconds   authorize 下发 state 的存活时长（秒）
     * @param ticketTtlSeconds  一次性 ticket 的消费时限（秒）
     * @param clients           以逻辑名（agent/kb）为键的客户端注册表
     */
    public record Sso(long stateTtlSeconds, long ticketTtlSeconds, Map<String, SsoClient> clients) {
    }

    /**
     * 单个 SSO 消费方客户端注册项。
     *
     * @param id          客户端标识，兑换时凭据校验的 clientId
     * @param name        展示名（授权页用）
     * @param secret      客户端明文密钥（仅环境注入；校验路径用摘要）
     * @param callbackUrl 兑换成功后的精确回调地址（不做前缀匹配）
     * @param origins     该客户端允许的 Origin 白名单（CSRF 面）
     * @param audience    签发会话绑定的受众，兑换与核验须一致
     */
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
