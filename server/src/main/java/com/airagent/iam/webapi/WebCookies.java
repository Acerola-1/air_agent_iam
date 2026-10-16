package com.airagent.iam.webapi;

import com.airagent.iam.config.IamProperties;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * 浏览器 cookie 策略：host-only（不设 Domain）、SameSite=Lax、Path=/；
 * 生产 secureCookies=true 才使用 __Host- 前缀并置 Secure，本机 HTTP 使用独立 dev 名。
 * 会话句柄 cookie HttpOnly；CSRF cookie 供 JS 读取做双重提交，权威值以句柄绑定的库值为准。
 */
@Component
public class WebCookies {

    public static final String CSRF_HEADER = "X-CSRF-Token";

    private final IamProperties.Web web;

    public WebCookies(IamProperties props) {
        this.web = props.web();
    }

    public String sessionCookieName() {
        return web.secureCookies() ? web.sessionCookieProd() : web.sessionCookieDev();
    }

    public String csrfCookieName() {
        return web.secureCookies() ? web.csrfCookieProd() : web.csrfCookieDev();
    }

    public boolean secure() {
        return web.secureCookies();
    }

    public void issueSession(HttpServletResponse response, String rawHandle) {
        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie(rawHandle,
                Duration.ofSeconds(web.handleTtlSeconds())).toString());
    }

    public void issueCsrf(HttpServletResponse response, String csrf) {
        response.addHeader(HttpHeaders.SET_COOKIE, csrfCookie(csrf,
                Duration.ofSeconds(web.handleTtlSeconds())).toString());
    }

    public void expireSession(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                sessionCookie("", Duration.ZERO).toString());
    }

    public void expireCsrf(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                csrfCookie("", Duration.ZERO).toString());
    }

    private ResponseCookie sessionCookie(String value, Duration maxAge) {
        return ResponseCookie.from(sessionCookieName(), value)
                .httpOnly(true)
                .secure(web.secureCookies())
                .path("/")
                .sameSite("Lax")
                .maxAge(maxAge)
                .build();
    }

    private ResponseCookie csrfCookie(String value, Duration maxAge) {
        return ResponseCookie.from(csrfCookieName(), value)
                .httpOnly(false)
                .secure(web.secureCookies())
                .path("/")
                .sameSite("Lax")
                .maxAge(maxAge)
                .build();
    }
}
