package com.airagent.iam.webapi.controller;

import com.airagent.iam.webapi.WebCookies;
import com.airagent.iam.webapi.service.BrowserSessionService;
import com.airagent.iam.webapi.vo.CsrfVO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** 浏览器匿名上下文与 CSRF；保留既有别名。 */
@RestController
public class BrowserCsrfController {
    private final BrowserSessionService browserSessions;
    private final WebCookies cookies;

    public BrowserCsrfController(BrowserSessionService browserSessions, WebCookies cookies) {
        this.browserSessions = browserSessions;
        this.cookies = cookies;
    }

    @GetMapping({"/web-api/csrf", "/web-api/auth/csrf"})
    public CsrfVO csrf(HttpServletRequest request, HttpServletResponse response) {
        String rawHandle = null;
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (cookies.sessionCookieName().equals(cookie.getName())) {
                    rawHandle = cookie.getValue();
                    break;
                }
            }
        }
        var handle = browserSessions.resolveCsrf(rawHandle);
        cookies.issueSession(response, handle.rawHandle());
        cookies.issueCsrf(response, handle.csrfToken());
        response.setHeader("Cache-Control", "no-store");
        return new CsrfVO(handle.csrfToken(), handle.expiresAt().toString());
    }
}
