package com.airagent.iam.security.internal;

import com.airagent.iam.web.error.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 内部端点（{@code /v1/internal/**}）的客户端准入组件：凭据核验 → scope 裁决 → 按客户端限流。
 *
 * <p>分层位置：安全层的 Spring 组件（{@link HandlerInterceptor} 实现），不是 HTTP 端点模型，
 * 因此不带 Swagger 注解；被裁决的主体是已登记的内部客户端（{@link InternalClient}），
 * 与人类会话的 Bearer 拦截器
 * {@link com.airagent.iam.web.BearerAuthInterceptor} 分属不同鉴权面——后者只注册在
 * {@code /v1/auth/**}、{@code /v1/admin/**}，{@code /v1/internal/sso/exchange} 另由
 * {@link com.airagent.iam.webapi.sso.SsoExchangeInterceptor} 处理（查 {@code iam.sso_clients}），
 * 三条链路的凭据来源互斥，不存在同一个头被两种主体重复接受的路径。
 *
 * <p>实际执行位置：本组件虽实现了 {@link #preHandle}，但当前装配并未把它注册进
 * {@code /v1/internal/**} 的拦截器链（见 {@link com.airagent.iam.config.WebMvcConfiguration}），
 * 实时端点在 {@link com.airagent.iam.internal.controller.InternalApiController} 内显式调用
 * {@link #authenticateAndAuthorize(String, String)}——目的是把认证耗时也纳入
 * {@link com.airagent.iam.web.async.IdentityDeadlineExecutor} 的端到端预算，并使凭据核验与用例执行处于同一个失败关闭预算内。
 * {@link #preHandle} 因此主要服务于拦截器语义与集成测试的直接调用。
 *
 * <p>失败关闭：限流与数据库依赖故障一律拒绝（429/503），绝不因"读不到"而放行；
 * 端点未登记即 403，不存在"默认 scope 为空则放行"的路径。
 *
 * @author Acerola
 */
@Component
public class InternalClientInterceptor implements HandlerInterceptor {

    /**
     * 已认证客户端写入 request 属性的键名。仅由 {@link #preHandle} 写入；
     * 实时端点走显式调用路径，直接从方法返回值取客户端，不读该属性。
     */
    public static final String CLIENT_ATTRIBUTE = "iam.internalClient";

    /** 内部客户端凭据核验组件（Basic/Bearer 双形态）。 */
    private final InternalClientAuthenticator authenticator;

    /** 按客户端的 Redis 固定窗口准入限流器。 */
    private final RateLimiter rateLimiter;

    /**
     * 构造准入组件。
     *
     * @param authenticator 内部客户端凭据核验组件
     * @param rateLimiter   限流器，以 {@link RateLimiter#SCOPE_INTERNAL} 域按客户端计数
     */
    public InternalClientInterceptor(InternalClientAuthenticator authenticator,
                                     RateLimiter rateLimiter) {
        this.authenticator = authenticator;
        this.rateLimiter = rateLimiter;
    }

    /**
     * 拦截器入口：完成认证与授权后把客户端挂到请求属性，并声明响应不可缓存。
     *
     * <p>{@code Cache-Control: no-store} 与 {@code RequestIdFilter} 的全局设置同值，
     * 属重复写入；本方法总是返回 {@code true}，不通过返回 {@code false} 的方式拒绝——
     * 拒绝一律以 {@link ApiException} 抛出，交由全局异常处理器生成错误信封。
     *
     * @param request  当前请求，只读 {@code Authorization} 头与 {@code getRequestURI()}
     * @param response 待出站的响应，仅写入 {@code Cache-Control} 头
     * @param handler  目标处理器，本实现不使用
     * @return 恒为 {@code true}，表示继续处理
     * @throws ApiException 401 凭据缺失或无效；403 端点未登记或客户端缺少所需 scope；
     *                      429 命中按客户端的准入限流；503 限流或核验依赖不可用
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        InternalClient client = authenticateAndAuthorize(request.getHeader("Authorization"), request.getRequestURI());
        request.setAttribute(CLIENT_ATTRIBUTE, client);
        response.setHeader("Cache-Control", "no-store");
        return true;
    }

    /**
     * 认证 + 授权 + 限流的唯一裁决入口，顺序固定：凭据 → scope → 限流。
     *
     * <p>先认证再限流，意味着限流计数键的主体（{@code client_id}）一定是已核验值，
     * 未认证流量不消耗任何客户端的窗口配额；副作用是攻击者可低成本触发数据库核验，
     * 由数据库单往返与连接池上限承担。scope 判定先于限流，缺权限的客户端不会占用其配额。
     *
     * @param authorization 原始 {@code Authorization} 头，允许 {@code null}（由认证器转 401）
     * @param uri           请求 URI（{@code getRequestURI()} 口径，不含查询串），用于解析所需 scope
     * @return 已通过凭据、scope 与限流三重裁决的客户端
     * @throws ApiException 401 凭据无效；403 URI 不在 {@link #requiredScope(String)} 白名单内
     *                      （消息为"未注册的内部端点"），或客户端未被授予该端点要求的 scope；
     *                      429 命中限流；503 核验或限流依赖不可用
     */
    public InternalClient authenticateAndAuthorize(String authorization, String uri) {
        InternalClient client = authenticator.authenticate(authorization);
        String requiredScope = requiredScope(uri);
        if (requiredScope == null) {
            throw ApiException.forbidden("未注册的内部端点");
        }
        if (!client.hasScope(requiredScope)) {
            throw ApiException.forbidden("客户端缺少 scope: " + requiredScope);
        }
        rateLimiter.check(RateLimiter.SCOPE_INTERNAL, client.clientId());
        return client;
    }

    /**
     * URI 到所需 scope 的白名单映射：按 URI 结尾精确匹配，未命中即拒绝（默认拒绝，无兜底放行）。
     *
     * @param uri 请求 URI，必须非空（来自 {@code getRequestURI()}，不含查询串）；
     *            为空指针场景不在本方法处理范围
     * @return {@code identity:introspect}（主体内省端点）、{@code runtime-ticket:issue}
     *         （运行票据签发端点），未登记路径返回 {@code null} 由调用方转 403
     */
    private String requiredScope(String uri) {
        if (uri.endsWith("/v1/internal/identity/introspect")) {
            return "identity:introspect";
        }
        if (uri.endsWith("/v1/internal/runtime-tickets")) {
            return "runtime-ticket:issue";
        }
        if (uri.endsWith("/v1/internal/tenants/status")) {
            return "tenant:status:read";
        }
        return null;
    }
}
