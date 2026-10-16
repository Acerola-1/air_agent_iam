package com.airagent.iam.webapi.sso;

import com.airagent.iam.security.internal.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * /v1/internal/sso/exchange 专用拦截：sso_clients Basic 核验 + 按客户端限流；
 * 与 internal_clients 的 introspect/runtime-tickets 凭据体系互斥。
 */
@Component
public class SsoExchangeInterceptor implements HandlerInterceptor {

    public static final String SSO_CLIENT_ATTRIBUTE = "iam.ssoClient";

    private final SsoClientAuthenticator authenticator;
    private final RateLimiter rateLimiter;

    public SsoExchangeInterceptor(SsoClientAuthenticator authenticator, RateLimiter rateLimiter) {
        this.authenticator = authenticator;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        SsoClientView client = authenticator.authenticate(request.getHeader("Authorization"));
        rateLimiter.check(RateLimiter.SCOPE_INTERNAL, "sso-exchange:" + client.clientId());
        request.setAttribute(SSO_CLIENT_ATTRIBUTE, client);
        response.setHeader("Cache-Control", "no-store");
        return true;
    }
}
