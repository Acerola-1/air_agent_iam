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
 * {@code /web-api} 写操作的同源 + CSRF 双保险拦截器（{@code HandlerInterceptor}）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.config.WebMvcConfiguration} 挂载在
 * {@code /web-api/**} 与 {@code /v1/sso/authorize}，<em>不</em>排除登录与 CSRF 端点——
 * 登录（{@code POST /web-api/auth/login}）同样要先取得匿名句柄并通过同源+CSRF 检查，
 * "登录也不例外"。它与 {@link BrowserSessionInterceptor} 分工：本拦截器只做
 * <em>Origin/CSRF/Authorization 头</em>防护，权威会话核验在后者完成；两者通过
 * {@link BrowserSessionInterceptor#HANDLE_ROW_ATTRIBUTE} 与
 * {@link BrowserSessionInterceptor#HANDLE_RAW_ATTRIBUTE} 传递已解析句柄，避免二次读库。
 *
 * <p>三重防护（缺一即 403）：
 * <ol>
 *   <li>拒绝任何浏览器直送的 {@code Authorization} 头，防止 Bearer 令牌与浏览器句柄混用；</li>
 *   <li>写操作（非 {@link #SAFE_METHODS}）要求 {@code Origin} 与请求同源<em>精确</em>相等，
 *       或落在 {@code iam.web.allowed-origins} 精确白名单内（无通配、无宽 Domain）；</li>
 *   <li>写操作要求 {@code X-CSRF-Token} 头与该句柄在 iam.browser_handles 绑定的 CSRF
 *       常量时间相等——权威值来自数据库，而非 JS 可读 Cookie，故伪造 Cookie 不通过。</li>
 * </ol>
 *
 * @author Acerola
 */
@Component
public class CsrfOriginInterceptor implements HandlerInterceptor {

    /** 无副作用、不触发 CSRF 校验的 HTTP 方法集合（仍执行 {@code Authorization} 头拒绝）。 */
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    /** 浏览器句柄/会话解析。 */
    private final BrowserSessionService browserSessions;
    /** Cookie 读取辅助。 */
    private final WebCookies cookies;
    /** 浏览器适配配置（Origin 白名单等）。 */
    private final IamProperties.Web web;

    /**
     * 构造拦截器。
     *
     * @param browserSessions 句柄解析服务（{@link BrowserSessionService#resolve}）
     * @param cookies         Cookie 装配工具；提供当前环境的会话 Cookie 名与 {@code CSRF_HEADER}
     * @param props           {@code iam.*} 配置；取 {@code iam.web.secure-cookies} 与
     *                        {@code iam.web.allowed-origins}
     */
    public CsrfOriginInterceptor(BrowserSessionService browserSessions,
                                 WebCookies cookies, IamProperties props) {
        this.browserSessions = browserSessions;
        this.cookies = cookies;
        this.web = props.web();
    }

    /**
     * 请求前置防护：先拒 {@code Authorization} 头，再对写操作施加 Origin + CSRF 检查。
     *
     * <p>{@code Authorization} 拒绝先于安全方法判断，因此 GET 携带 Bearer 也会被 403；
     * 每次进入都强制 {@code Cache-Control: no-store} 与 {@code Pragma: no-cache}。
     *
     * @param request  当前 HTTP 请求
     * @param response 当前 HTTP 响应；本方法写入缓存相关响应头
     * @param handler  目标 Controller 方法句柄；不区分类型
     * @return {@code true} 放行（安全方法，或写操作已通过 Origin+CSRF 校验）
     * @throws ApiException 403 携带 {@code Authorization} 头；或缺 Origin / Origin 越界 /
     *                      句柄缺失或已过期 / CSRF 不匹配
     */
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

    /**
     * 同源校验：{@code Origin} 必须非空、非字面量 {@code "null"}，且与请求同源或白名单<em>精确</em>相等。
     *
     * <p>同源基准为 {@code scheme + "://" + serverName + ":" + serverPort}，其中 scheme 由
     * 配置 {@code iam.web.secure-cookies} 推导（{@code true → https}，{@code false → http}）
     * 而非请求实际协议——因此部署协议必须与该开关一致，否则真实同源也会落白名单方通过。
     * 白名单 {@code iam.web.allowed-origins} 是精确字符串集合（默认仅本机 Vite 回环
     * {@code http://127.0.0.1:19101} 与 {@code http://localhost:19101}），不支持通配。
     *
     * @param request 当前 HTTP 请求；读取 {@code Origin} 头与服务端 name/port
     * @throws ApiException 403 缺 Origin、Origin 空白、Origin 为 {@code "null"}，或既非同源也不在白名单
     */
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

    /**
     * CSRF 双提交校验：解析句柄 → 取库绑定的 CSRF → 与 {@code X-CSRF-Token} 常量时间比对。
     *
     * <p>写路径的句柄必须真实存在且未吊销/未过期（匿名句柄同样允许，以支持登录前的 CSRF），
     * 否则 403 并提示重新获取 CSRF。校验通过后把句柄与原始值写入 request attribute，
     * 供 {@link BrowserSessionInterceptor} 复用而不重复读库。
     *
     * @param request 当前 HTTP 请求；读取会话 Cookie 与 {@code X-CSRF-Token} 头
     * @throws ApiException 403 句柄缺失/已过期/已吊销，或 CSRF 头缺失、与库值不等
     */
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

    /**
     * 从请求 Cookie 数组中挑出当前环境的会话句柄原始值（与
     * {@link BrowserSessionInterceptor} 的读取口径一致）。
     *
     * @param request 当前 HTTP 请求；{@code getCookies()} 可能为 {@code null}
     * @return 首个非空非空白同名 Cookie 的值；无匹配返回 {@code null}
     */
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

    /**
     * UTF-8 字节级常量时间比较，抵御 CSRF 令牌时序侧信道。
     *
     * <p>两串都按 UTF-8 编码后交给 {@link MessageDigest#isEqual(byte[], byte[])}；
     * 调用方保证 {@code a} 非空（头缺失已在上游短路），{@code b} 为库值（列 NOT NULL）。
     *
     * @param a 客户端回传的 CSRF 头值
     * @param b 句柄在 iam.browser_handles 绑定的权威 CSRF 值
     * @return 字节完全相等返回 {@code true}
     */
    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
