package com.airagent.iam.web;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.web.error.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 不透明 Bearer 令牌拦截器：Sa-Token Redis 存在性 + PG 主库权威快照双验。
 * 任何依赖异常由全局异常处理器转 503（失败关闭）。
 */
@Component
public class BearerAuthInterceptor implements HandlerInterceptor {

    public static final String CURRENT_SESSION_ATTRIBUTE = "iam.currentSession";
    public static final String RAW_TOKEN_ATTRIBUTE = "iam.rawToken";
    private static final String BEARER_PREFIX = "Bearer ";

    private final SessionService sessionService;

    public BearerAuthInterceptor(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public static String bearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            throw ApiException.unauthenticated("缺少 Bearer 访问令牌");
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            throw ApiException.unauthenticated("访问令牌为空");
        }
        return token;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String token = bearerToken(request);
        CurrentSession current = sessionService.requireCurrent(token);
        request.setAttribute(CURRENT_SESSION_ATTRIBUTE, current);
        request.setAttribute(RAW_TOKEN_ATTRIBUTE, token);
        // 身份响应一律不进浏览器/中间件缓存
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        return true;
    }
}
