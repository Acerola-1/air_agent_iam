package com.airagent.iam.webapi.sso;

import com.airagent.iam.security.internal.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * {@code /v1/internal/sso/exchange} 专用拦截器（认证面：SSO 客户端凭据）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.config.WebMvcConfiguration} <em>只</em>挂载在
 * {@code /v1/internal/sso/exchange} 这一条路径上，是本拦截器与 {@link SsoClientAuthenticator}
 * 唯一的接线点；Controller 因此能假定请求属性
 * {@link #SSO_CLIENT_ATTRIBUTE} 必然已注入。它与浏览器面拦截器互不相干：
 * 本路径<em>不</em>经 {@code BrowserSessionInterceptor}，也不经
 * {@code CsrfOriginInterceptor}（后者只覆盖 {@code /web-api/**} 与 {@code /v1/sso/authorize}，
 * 且会拒绝任何 {@code Authorization} 头）——兑换是服务端到服务端调用，客户端凭据正是它的
 * 唯一授权来源。
 *
 * <p>与 {@code internal_clients} 凭据体系互斥：本拦截器核验的是 {@code iam.sso_clients}
 * 登记的 SSO 应用凭据（Bearer 客户端密钥，兼容 Basic 的 {@code client_id:client_secret}，
 * 见 {@link SsoClientAuthenticator}），与
 * {@link com.airagent.iam.security.internal.InternalClientInterceptor} 使用的
 * introspect/runtime-tickets 内部客户端是两套登记表与两套受众，凭据不可互换。
 *
 * <p>校验顺序即限速口径：<em>先</em>认证凭据、<em>后</em>按已认证的 clientId 计数限流。
 * 顺序的意义是凭据无效的请求不会占用任何客户端的配额，也无法通过轮换凭据绕开他人配额；
 * 代价是每次失败认证都要走一遍数据库函数（函数内只比摘要，不做昂贵运算）。
 * 限流域为 {@link RateLimiter#SCOPE_INTERNAL}，key {@code sso-exchange:<clientId>}，
 * 阈值取 {@code iam.rate-limit.internal-limit}（缺省 600）每
 * {@code iam.rate-limit.window-seconds}（缺省 60 秒）一个固定窗口；
 * {@code iam.rate-limit.enabled=false} 时短路，Redis 连接失败按 503 失败关闭。
 *
 * @author Acerola
 */
@Component
public class SsoExchangeInterceptor implements HandlerInterceptor {

    /**
     * request attribute key：已核验的 {@link SsoClientView}；仅由本拦截器写入，
     * 只存在于单次请求作用域，不得跨请求复用作为放行依据。
     */
    public static final String SSO_CLIENT_ATTRIBUTE = "iam.ssoClient";

    /** 兑换客户端凭据核验器 */
    private final SsoClientAuthenticator authenticator;
    /** 按客户端固定窗口限流 */
    private final RateLimiter rateLimiter;

    /**
     * 构造拦截器，全部依赖经 Spring 构造注入。
     *
     * @param authenticator SSO 客户端凭据核验器（Bearer 优先、兼容 Basic）
     * @param rateLimiter   Redis 固定窗口限流器，按已认证客户端计数
     */
    public SsoExchangeInterceptor(SsoClientAuthenticator authenticator, RateLimiter rateLimiter) {
        this.authenticator = authenticator;
        this.rateLimiter = rateLimiter;
    }

    /**
     * 请求前置：凭据核验 → 客户端限速 → 装配已认证视图 → 关闭缓存。
     *
     * <p>失败一律抛异常中断链路，由 {@code GlobalExceptionHandler} 转统一错误信封；
     * 因此 {@code Cache-Control: no-store} 只在放行路径上写入，被拒的请求响应不带该头。
     * 兑换响应体含一次性访问令牌，关闭缓存是必要约束——该头确保令牌不被中间层或浏览器留存。
     *
     * @param request  当前 HTTP 请求；只读取 {@code Authorization} 头
     * @param response 当前 HTTP 响应；写入 {@code Cache-Control}
     * @param handler  目标 Controller 方法句柄；本拦截器不区分 handler 类型
     * @return 恒返回 {@code true}（未通过即抛 {@link com.airagent.iam.web.error.ApiException}）
     * @throws com.airagent.iam.web.error.ApiException 401 凭据缺失、格式非法或核验不通过；
     *                                                429 该客户端在窗口内兑换次数超限；
     *                                                503 Redis 限流依赖故障
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        SsoClientView client = authenticator.authenticate(request.getHeader("Authorization"));
        rateLimiter.check(RateLimiter.SCOPE_INTERNAL, "sso-exchange:" + client.clientId());
        request.setAttribute(SSO_CLIENT_ATTRIBUTE, client);
        response.setHeader("Cache-Control", "no-store");
        return true;
    }
}
