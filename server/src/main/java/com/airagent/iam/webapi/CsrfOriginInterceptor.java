package com.airagent.iam.webapi;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.service.BrowserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * /web-api 写操作的同源与 CSRF 双保险（登录也不例外）。
 * Origin 必须与精确白名单或请求同源完全相等（无通配、无宽 Domain）；
 * X-CSRF-Token 必须与句柄在库绑定的 CSRF 常量时间相等。另拒绝任何浏览器直送
 * Authorization 头，防止 Bearer 与浏览器句柄混用。
 */
@Component
public class CsrfOriginInterceptor implements HandlerInterceptor {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final BrowserSessionService browserSessions;
    private final WebCookies cookies;
    private final IamProperties.Web web;

    public CsrfOriginInterceptor(BrowserSessionService browserSessions,
                                 WebCookies cookies, IamProperties props) {
        this.browserSessions = browserSessions;
        this.cookies = cookies;
        this.web = props.web();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        if (request.getHeader("Authorization") != null) {
            throw ApiException.forbidden("浏览器适配层不接受 Authorization 头");
        }
        if (SAFE_METHODS.contains(request.getMethod())) {
            return true;
        }
        requireOrigin(request);
        requireCsrf(request);
        return true;
    }

    private void requireOrigin(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isBlank() || "null".equals(origin)) {
            throw ApiException.forbidden("缺少 Origin，拒绝写操作");
        }
        String scheme = web.secureCookies() ? "https" : "http";
        String sameOrigin = scheme + "://" + request.getServerName() + ":" + request.getServerPort();
        boolean allowed = origin.equals(sameOrigin)
                || (web.allowedOrigins() != null && web.allowedOrigins().contains(origin));
        if (!allowed) {
            throw ApiException.forbidden("Origin 不在允许范围内");
        }
    }

    private void requireCsrf(HttpServletRequest request) {
        String rawHandle = cookieValue(request);
        BrowserHandleRow row = browserSessions.resolve(rawHandle);
        if (row == null || row.revokedOrExpired()) {
            throw ApiException.forbidden("浏览器上下文不存在或已过期，请重新获取 CSRF");
        }
        String header = request.getHeader(WebCookies.CSRF_HEADER);
        if (header == null || !constantTimeEquals(header, row.csrfToken())) {
            throw ApiException.forbidden("CSRF 校验失败");
        }
        request.setAttribute(BrowserSessionInterceptor.HANDLE_ROW_ATTRIBUTE, row);
        request.setAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE, rawHandle);
    }

    private String cookieValue(HttpServletRequest request) {
        jakarta.servlet.http.Cookie[] requestCookies = request.getCookies();
        if (requestCookies == null) {
            return null;
        }
        String sessionCookie = cookies.sessionCookieName();
        for (jakarta.servlet.http.Cookie cookie : requestCookies) {
            if (sessionCookie.equals(cookie.getName()) && cookie.getValue() != null
                    && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
