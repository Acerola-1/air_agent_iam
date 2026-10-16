package com.airagent.iam.security.internal;

import com.airagent.iam.web.error.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * /v1/internal/** 仅接受内部客户端 Basic 认证（与人类 Bearer 拦截器互斥），
 * 并按端点要求校验 scope；同时施加按客户端的准入限流。
 */
@Component
public class InternalClientInterceptor implements HandlerInterceptor {

    public static final String CLIENT_ATTRIBUTE = "iam.internalClient";

    private final InternalClientAuthenticator authenticator;
    private final RateLimiter rateLimiter;

    public InternalClientInterceptor(InternalClientAuthenticator authenticator,
                                     RateLimiter rateLimiter) {
        this.authenticator = authenticator;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        InternalClient client = authenticateAndAuthorize(request.getHeader("Authorization"), request.getRequestURI());
        request.setAttribute(CLIENT_ATTRIBUTE, client);
        response.setHeader("Cache-Control", "no-store");
        return true;
    }

    /** 由实时端点在总预算内执行，兼容拦截器测试及独立调用。 */
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

    private String requiredScope(String uri) {
        if (uri.endsWith("/v1/internal/identity/introspect")) {
            return "identity:introspect";
        }
        if (uri.endsWith("/v1/internal/runtime-tickets")) {
            return "runtime-ticket:issue";
        }
        return null;
    }
}
