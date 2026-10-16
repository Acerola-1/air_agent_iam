package com.airagent.iam.webapi;

import com.airagent.iam.config.IamProperties;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * 浏览器 {@code /web-api} 适配层的 Cookie 装配工具（内部组件，无 HTTP 入口）。
 *
 * <p>分层位置：被 {@link BrowserSessionInterceptor}、{@link CsrfOriginInterceptor}、
 * {@link com.airagent.iam.webapi.controller.WebApiAuthController}、
 * {@link com.airagent.iam.webapi.controller.BrowserCsrfController} 共用；本身不
 * 访问数据库，也不参与任何授权判定，仅按 {@link IamProperties.Web} 中的开关与
 * 命名拼装 {@link ResponseCookie} 并通过 {@code Set-Cookie} 头下发。
 *
 * <p>命名与安全属性：{@code iam.web.secure-cookies=true}（生产/HTTPS 部署）走 {@code __Host-}
 * 前缀名 {@code __Host-air_iam_session} / {@code __Host-air_iam_csrf} 且 {@code Secure}；
 * {@code false}（本服务默认只监听回环、走 HTTP）走 dev 名 {@code air_iam_dev_session} /
 * {@code air_iam_dev_csrf} 且 {@code Secure=false}。两变体都固定 {@code Path=/}、
 * {@code SameSite=Lax}，<em>从不</em>设置 {@code Domain}，与 {@code __Host-} 前缀的
 * "host-only"约束一致；{@code __Host-} 前缀本身由配置名直接携带，代码不再二次拼接。
 *
 * <p>会话句柄 Cookie 为 {@code HttpOnly}（JS 不可读，避免 XSS 偷取）；CSRF Cookie
 * 允许 JS 读取以完成"双提交"（前端把该 Cookie 值放到 {@link #CSRF_HEADER} 请求头回传），
 * 权威值仍存于 iam.browser_handles.csrf_token 列，由 {@link CsrfOriginInterceptor}
 * 常量时间比对，前端 Cookie 被伪造也不通过。
 *
 * <p>失效与续期：{@code issueSession} / {@code issueCsrf} 以
 * {@code iam.web.handle-ttl-seconds}（默认 604800 秒 = 7 天，对齐
 * {@code iam.session.idle-timeout-seconds}）为 {@code Max-Age}；{@code expireSession} /
 * {@code expireCsrf} 以 {@link Duration#ZERO} 加空值即刻清除同名 Cookie。
 *
 * @author Acerola
 */
@Component
public class WebCookies {

    /** 双提交 CSRF 请求头名；写操作必须携带与句柄库值一致的令牌。 */
    public static final String CSRF_HEADER = "X-CSRF-Token";

    /** Cookie 名称与 Secure 策略配置。 */
    private final IamProperties.Web web;

    /**
     * 构造 Cookie 装配器。
     *
     * @param props {@code iam.*} 配置；仅使用其 {@code web} 段（cookie 命名、
     *              {@code secure-cookies} 开关、{@code handle-ttl-seconds}）
     */
    public WebCookies(IamProperties props) {
        this.web = props.web();
    }

    /**
     * 当前环境下的会话句柄 Cookie 名。
     *
     * @return {@code secureCookies=true} 返回生产 {@code __Host-} 名，否则返回 dev 名；
     *         命名缺失时返回 {@code null}（由配置层保证不出现）
     */
    public String sessionCookieName() {
        return web.secureCookies() ? web.sessionCookieProd() : web.sessionCookieDev();
    }

    /**
     * 当前环境下的 CSRF Cookie 名（前端 JS 可读、用于回填 {@link #CSRF_HEADER}）。
     *
     * @return 生产或 dev CSRF Cookie 名；命名缺失时返回 {@code null}
     */
    public String csrfCookieName() {
        return web.secureCookies() ? web.csrfCookieProd() : web.csrfCookieDev();
    }

    /**
     * 是否按生产 HTTPS 语义下发 Cookie（{@code Secure} 属性与 {@code __Host-} 前缀同源判定）。
     *
     * @return {@code iam.web.secure-cookies} 的当前值
     */
    public boolean secure() {
        return web.secureCookies();
    }

    /**
     * 下发/续期会话句柄 Cookie（HttpOnly）。
     *
     * <p>不检查当前是否已存在同名 Cookie——{@code Set-Cookie} 覆盖同名同 Path 的旧值。
     * 登录成功时调用者应先由 {@link com.airagent.iam.webapi.service.BrowserSessionService#bind}
     * 轮换句柄，再调用本方法下发新原始句柄，避免会话固定攻击。
     *
     * @param response   待写入 {@code Set-Cookie} 的响应
     * @param rawHandle  原始句柄（{@code OpaqueTokens.newRawToken()} 结果），
     *                   调用方保证非空；库内仅存其 SHA-256 摘要
     */
    public void issueSession(HttpServletResponse response, String rawHandle) {
        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie(rawHandle,
                Duration.ofSeconds(web.handleTtlSeconds())).toString());
    }

    /**
     * 下发/续期 CSRF Cookie（JS 可读）。
     *
     * @param response 待写入 {@code Set-Cookie} 的响应
     * @param csrf     与当前句柄库值绑定的 CSRF 令牌；权威校验以库值为准
     */
    public void issueCsrf(HttpServletResponse response, String csrf) {
        response.addHeader(HttpHeaders.SET_COOKIE, csrfCookie(csrf,
                Duration.ofSeconds(web.handleTtlSeconds())).toString());
    }

    /**
     * 即刻失效会话句柄 Cookie（登出与登录轮换旧句柄时调用）。
     *
     * <p>写空值 + {@code Max-Age=0}；不依赖当前 {@code rawHandle} 内容——浏览器按
     * 同名同 Path 匹配清除，即便伪造旧值也会被覆盖。
     *
     * @param response 待写入 {@code Set-Cookie} 的响应
     */
    public void expireSession(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                sessionCookie("", Duration.ZERO).toString());
    }

    /**
     * 即刻失效 CSRF Cookie；与 {@link #expireSession} 配对使用。
     *
     * @param response 待写入 {@code Set-Cookie} 的响应
     */
    public void expireCsrf(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                csrfCookie("", Duration.ZERO).toString());
    }

    /**
     * 装配会话句柄 Cookie：HttpOnly、Path=/、SameSite=Lax、无 Domain；
     * {@code Secure} 取决于 {@code iam.web.secure-cookies}。
     *
     * @param value   Cookie 值（原始句柄或空串）
     * @param maxAge  浏览器侧存活时长；{@link Duration#ZERO} 表示即刻失效
     * @return 用于写 {@code Set-Cookie} 的 {@link ResponseCookie}
     */
    private ResponseCookie sessionCookie(String value, Duration maxAge) {
        return ResponseCookie.from(sessionCookieName(), value)
                .httpOnly(true)
                .secure(web.secureCookies())
                .path("/")
                .sameSite("Lax")
                .maxAge(maxAge)
                .build();
    }

    /**
     * 装配 CSRF Cookie：JS 可读（{@code HttpOnly=false}）、Path=/、SameSite=Lax、无 Domain；
     * {@code Secure} 与句柄 Cookie 同步取 {@code iam.web.secure-cookies}。
     *
     * @param value  Cookie 值（CSRF 令牌或空串）
     * @param maxAge 浏览器侧存活时长；{@link Duration#ZERO} 表示即刻失效
     * @return 用于写 {@code Set-Cookie} 的 {@link ResponseCookie}
     */
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
