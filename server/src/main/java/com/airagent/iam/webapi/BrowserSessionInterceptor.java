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
 * 浏览器会话拦截器（{@code HandlerInterceptor}，{@code /web-api} 受保护端点的权威核验入口）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.config.WebMvcConfiguration} 挂载在
 * {@code /web-api/auth/**}、{@code /web-api/admin/**}、{@code /web-api/sso/start} 与
 * {@code /v1/sso/authorize} 上；{@code /web-api/auth/csrf} 与 {@code /web-api/auth/login}
 * 为<em>公开</em>端点被显式排除（登录前的浏览器尚无会话）。它<em>不</em>访问数据库——
 * 句柄读经 {@link BrowserSessionService} 落到 SECURITY DEFINER 函数；权威核验复用
 * Bearer 链路完全相同的 {@link SessionService#requireCurrentBySessionId(java.util.UUID)}：
 * 服务端按会话 id 取回令牌摘要，走"Redis Sa-Token 存活 + PG 主库权威快照"双检。
 *
 * <p>与 {@link CsrfOriginInterceptor} 的协同：Spring MVC 按注册顺序执行，写操作先经过
 * CsrfOriginInterceptor——后者若解析句柄成功，会把
 * {@link #HANDLE_RAW_ATTRIBUTE} 与 {@link #HANDLE_ROW_ATTRIBUTE} 塞进 request attribute
 * 以避免此处二次读库；GET/HEAD/OPTIONS 安全方法 CsrfOriginInterceptor 会短路，本拦截器
 * 自行从 Cookie 读取。核验通过后本拦截器以<em>与 Bearer 相同</em>的 key
 * {@code BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE} 写入
 * {@link CurrentSession}，管理 Controller（{@code UserAdminController} 等）零差异复用。
 *
 * <p>响应头与副作用：每次进入都强制 {@code Cache-Control: no-store} 与 {@code Pragma: no-cache}
 * 关闭浏览器/中间层缓存；核验通过的活跃会话同步 {@link BrowserSessionService#touch} 滑动
 * 句柄 TTL，与权威会话的空闲计时口径对齐（{@code iam.web.handle-ttl-seconds}）。
 *
 * @author Acerola
 */
@Component
public class BrowserSessionInterceptor implements HandlerInterceptor {

    /** request attribute key：已解析的 {@link BrowserHandleRow}；由本拦截器或 CsrfOriginInterceptor 写入。 */
    public static final String HANDLE_ROW_ATTRIBUTE = "iam.browser.handleRow";
    /** request attribute key：已读取的原始句柄字符串；避免写路径的两次 Cookie 扫描。 */
    public static final String HANDLE_RAW_ATTRIBUTE = "iam.browser.handleRaw";

    /** 浏览器句柄/会话服务。 */
    private final BrowserSessionService browserSessions;
    /** 中央会话权威服务。 */
    private final SessionService sessionService;
    /** Cookie 下发组件。 */
    private final WebCookies cookies;

    /**
     * 构造拦截器，全部依赖经 Spring 构造注入。
     *
     * @param browserSessions 句柄生命周期服务（解析与滑动 TTL）
     * @param sessionService  权威会话服务；提供 {@link SessionService#requireCurrentBySessionId}
     * @param cookies         Cookie 装配工具；本拦截器只用它取当前环境的会话 Cookie 名
     */
    public BrowserSessionInterceptor(BrowserSessionService browserSessions,
                                     SessionService sessionService,
                                     WebCookies cookies) {
        this.browserSessions = browserSessions;
        this.sessionService = sessionService;
        this.cookies = cookies;
    }

    /**
     * 句柄→会话解析 + 权威双检 + 请求属性装配。
     *
     * <p>失效路径依次：缺 Cookie 且 attribute 未注入 → 401；句柄不存在（伪造）或已吊销/
     * 过期 → 401；匿名句柄（{@code sessionId == null}，未走登录） → 401。
     * 权威核验（Redis 存活 + PG 快照）失败按 {@link SessionService#requireCurrentBySessionId}
     * 语义映射为 401/403/503——PG 侧会话被撤销、账号停用、企业停用与授权代次变旧都在此
     * 即时反映；Redis 依赖类异常由 GlobalExceptionHandler 兜底 503（失败关闭）。
     *
     * @param request  当前 HTTP 请求；Cookie 名与句柄摘要解析在此完成
     * @param response 当前 HTTP 响应；本方法写入 {@code Cache-Control}/{@code Pragma} 头
     * @param handler  目标 Controller 方法句柄；本拦截器不区分 handler 类型
     * @return 恒返回 {@code true}（未通过即抛 {@link ApiException} 中断链路）
     * @throws ApiException 401 缺句柄/句柄失效/匿名句柄/权威快照缺失或已撤销或过期或代次变旧；
     *                      403 企业停用或成员关系停用；503 Redis/PG 依赖故障
     */
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

    /**
     * 从请求 Cookie 数组中挑出当前环境的会话句柄值。
     *
     * <p>Cookie 名由 {@link WebCookies#sessionCookieName()} 决定（{@code air_iam_dev_session}
     * 或 {@code __Host-air_iam_session}）；只按<em>精确名</em>匹配，不接受前缀/通配。
     *
     * @param request 当前 HTTP 请求；{@code getCookies()} 可能为 {@code null}
     * @return 首个非空非空白同名 Cookie 的原始值；无匹配返回 {@code null}
     */
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
