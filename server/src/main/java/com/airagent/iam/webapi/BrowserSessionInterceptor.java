package com.airagent.iam.webapi;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.service.BrowserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * /web-api 受保护端点：解析 HttpOnly 句柄 → 会话 id 后执行与 Bearer 链路完全相同的
 * "Redis 存活 + PG 主库权威快照"双验，并把 {@link CurrentSession} 放入与
 * {@link BearerAuthInterceptor} 相同的请求属性，管理控制器零差异复用。
 */
@Component
public class BrowserSessionInterceptor implements HandlerInterceptor {

    public static final String HANDLE_ROW_ATTRIBUTE = "iam.browser.handleRow";
    public static final String HANDLE_RAW_ATTRIBUTE = "iam.browser.handleRaw";

    private final BrowserSessionService browserSessions;
    private final SessionService sessionService;
    private final WebCookies cookies;

    public BrowserSessionInterceptor(BrowserSessionService browserSessions,
                                     SessionService sessionService,
                                     WebCookies cookies) {
        this.browserSessions = browserSessions;
        this.sessionService = sessionService;
        this.cookies = cookies;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");

        String rawHandle = (String) request.getAttribute(HANDLE_RAW_ATTRIBUTE);
        BrowserHandleRow row = (BrowserHandleRow) request.getAttribute(HANDLE_ROW_ATTRIBUTE);
        if (rawHandle == null) {
            rawHandle = readCookie(request);
        }
        if (row == null) {
            row = browserSessions.resolve(rawHandle);
        }
        if (rawHandle == null || row == null) {
            throw ApiException.unauthenticated("缺少浏览器会话句柄");
        }
        if (row.revokedOrExpired()) {
            throw ApiException.unauthenticated("浏览器会话已失效，请重新登录");
        }
        if (row.sessionId() == null) {
            throw ApiException.unauthenticated("浏览器上下文尚未登录");
        }
        CurrentSession current = sessionService.requireCurrentBySessionId(row.sessionId());
        request.setAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE, current);
        request.setAttribute(HANDLE_ROW_ATTRIBUTE, row);
        request.setAttribute(HANDLE_RAW_ATTRIBUTE, rawHandle);
        browserSessions.touch(row);
        return true;
    }

    private String readCookie(HttpServletRequest request) {
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
}
