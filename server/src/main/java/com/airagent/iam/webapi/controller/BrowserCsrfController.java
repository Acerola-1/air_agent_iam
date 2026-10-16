package com.airagent.iam.webapi.controller;

import com.airagent.iam.webapi.WebCookies;
import com.airagent.iam.webapi.service.BrowserSessionService;
import com.airagent.iam.webapi.vo.CsrfVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 浏览器匿名上下文与 CSRF 获取入口（Controller 层，{@code /web-api} 适配面）。
 *
 * <p>分层位置：为尚未登录、或登录态需要刷新双提交 CSRF 的浏览器签发/复用句柄，
 * 编排全部在 {@link BrowserSessionService#resolveCsrf(String)}，Cookie 下发由
 * {@link WebCookies} 完成，本层只做 Cookie 读取、句柄轮换决策与响应装配。
 *
 * <p>公开性：{@code /web-api/auth/csrf} 在 {@link com.airagent.iam.config.WebMvcConfiguration}
 * 中被 {@link com.airagent.iam.webapi.BrowserSessionInterceptor} 显式排除，属
 * <em>无认证</em>端点；GET 属安全方法，{@link com.airagent.iam.webapi.CsrfOriginInterceptor}
 * 也只做 {@code Authorization} 头拒绝、不要求 Origin/CSRF。保留
 * {@code /web-api/csrf} 旧别名与新路径能力一致。
 *
 * <p>协作关系：签发结果随后被 {@code POST /web-api/auth/login} 作为
 * {@link BrowserSessionService#bind(String, java.util.UUID)} 的 {@code oldRawHandle} 传入，
 * 登录成功即完成会话固定防护轮换。
 *
 * @author Acerola
 */
@Tag(name = "浏览器 CSRF", description = "为 /web-api 浏览器适配层签发或复用匿名会话句柄与双提交 CSRF 令牌；公开端点，无需登录")
@RestController
public class BrowserCsrfController {

    /** 浏览器句柄/会话服务。 */
    private final BrowserSessionService browserSessions;
    /** Cookie 下发组件。 */
    private final WebCookies cookies;

    /**
     * 构造 CSRF 控制器。
     *
     * @param browserSessions 句柄生命周期服务
     * @param cookies         Cookie 装配工具
     */
    public BrowserCsrfController(BrowserSessionService browserSessions, WebCookies cookies) {
        this.browserSessions = browserSessions;
        this.cookies = cookies;
    }

    /**
     * 获取（或复用）当前浏览器的双提交 CSRF。
     *
     * <p>响应同时通过 {@code Set-Cookie} 下发 HttpOnly 会话句柄与 JS 可读 CSRF Cookie；
     * 对已登录且会话仍有效的浏览器幂等复用同一句柄，对匿名或会话已失效（如中央退出）
     * 的浏览器则吊销旧句柄并开新匿名句柄。响应带 {@code Cache-Control: no-store}。
     *
     * @param request  当前 HTTP 请求；从其同名会话 Cookie 读取原始句柄
     * @param response 当前 HTTP 响应；写入两枚 Cookie 与 no-store 头
     * @return {@link CsrfVO}：CSRF 令牌值与句柄到期时刻
     */
    @Operation(summary = "获取/复用浏览器 CSRF 与匿名句柄",
            description = "公开端点（BrowserSessionInterceptor 排除）：无需会话 Cookie 或 CSRF 即可调用。"
                    + "响应写入 HttpOnly 会话句柄 Cookie 与 JS 可读 CSRF Cookie，前端写操作需把返回的 "
                    + "csrf_token 放进 X-CSRF-Token 头回传；服务端以句柄在库绑定的 CSRF 常量时间比对，"
                    + "并另做 Origin 同源校验（二者共同构成双提交防护）。已登录会话幂等复用，"
                    + "匿名或会话失效则轮换为新句柄")
    @ApiResponse(responseCode = "200", description = "签发或复用成功，返回 CSRF 令牌与到期时刻并下发 Cookie")
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
