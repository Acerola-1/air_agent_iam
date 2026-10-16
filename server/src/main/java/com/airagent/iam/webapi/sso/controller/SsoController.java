package com.airagent.iam.webapi.sso.controller;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.sso.service.SsoAuthorizeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 中央 SSO 授权跳转 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>同一能力挂在两条等价路径上：浏览器面的 {@code /web-api/sso/start} 与契约面的
 * {@code /v1/sso/authorize}，二者由 {@link com.airagent.iam.config.WebMvcConfiguration}
 * 同时纳入 {@link BrowserSessionInterceptor} 与 {@code CsrfOriginInterceptor} 的覆盖范围，
 * 因此认证面是<em>浏览器中央会话 Cookie</em>（文档方案 {@code browserCookie}），
 * 并叠加同源防护：该拦截器对任何携带 {@code Authorization} 头的请求直接 403，
 * 浏览器会话与 Bearer 令牌不可混用；本端点是 GET 安全方法，故 Origin/CSRF 双提交检查短路。
 *
 * <p>场景：消费方应用把已登录的浏览器 303 到这里，中央签发一次性 {@code ticket} 并 303 回
 * <em>精确</em>登记的回调。中央<em>不</em>在此登录——没有有效会话就是 401，由前端引导登录。
 *
 * <p>本层只做会话与句柄提取、参数透传和 303 装配；注册校验、回调精确匹配、回环限制、
 * Origin 白名单、限流、state/ticket 登记与审计全部在
 * {@link SsoAuthorizeService} 裁决。失败以统一错误信封返回，<em>不</em>产生带错误码的重定向。
 *
 * @author Acerola
 */
@Tag(name = "中央 SSO 授权", description = "已登录浏览器发起的跨端授权跳转：校验注册客户端与精确回调后，"
        + "签发一次性 ticket 并 303 回登记的回调；需要浏览器中央会话 Cookie，写侧另受同源防护约束")
@RestController
public class SsoController {

    /** SSO 授权编排服务 */
    private final SsoAuthorizeService authorizeService;

    /**
     * 构造中央授权入口。
     *
     * @param authorizeService 授权业务服务，state/ticket 的登记与全部校验都在其中
     */
    public SsoController(SsoAuthorizeService authorizeService) {
        this.authorizeService = authorizeService;
    }

    /**
     * 授权跳转：登记一次性 state/ticket，并以 303 回到精确注册的回调。
     *
     * <p>请求属性来源：{@link CurrentSession} 与 {@link BrowserHandleRow} 都由
     * {@link BrowserSessionInterceptor} 在核验通过后写入（前者用 Bearer 链路同一 key
     * {@code BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE}）。受保护路径上二者必然非空——
     * 拦截器不放行就没有本方法；{@code Origin} 取请求头原值，可能为 {@code null}
     * （浏览器直接导航时不强制携带）。
     *
     * <p>跳转语义：状态码 303 See Other（{@code ResponseEntity.status(303)}），
     * {@code Location} 为 {@code redirect_uri + [?|&]ticket=...&state=...}，两个值都经 UTF-8 URL 编码。
     * 浏览器中央会话令牌<em>绝不</em>出现在该 URL、响应体或日志中；ticket 与 state 各只可用一次。
     *
     * <p>失败语义：<em>没有</em>错误重定向——所有拒绝都以统一错误信封直接响应，
     * 由 {@code GlobalExceptionHandler} 映射状态码；把失败原因回传给最终页面是消费方 BFF 的责任。
     *
     * @param request     当前 HTTP 请求；读取两个请求属性与 {@code Origin} 头
     * @param clientId    目标 SSO 客户端标识，必填非空白、长度上界 128；不存在或停用按 400 拒绝
     * @param redirectUri 期望回调地址，必填非空白、长度上界 512；必须与注册 {@code callback_url}
     *                    逐字相等（非前缀匹配）且为本机回环 http
     * @param state       消费方生成的一次性一致性值，必填，仅可打印非空白字符
     *                    （{@code \p{Graph}{1,256}}），授权后原样回传
     * @return 仅含 {@code Location} 头的 303 响应，无响应体
     */
    @Operation(summary = "发起中央 SSO 授权跳转（303 回精确回调）",
            description = "浏览器中央会话 Cookie 鉴权：必须已登录中央，无会话或句柄失效即 401。"
                    + "回调地址与注册值精确相等且限本机回环 http；Origin 头存在时必须命中该客户端登记的精确白名单。"
                    + "成功后按配置 iam.sso.state-ttl-seconds（600 秒）/ iam.sso.ticket-ttl-seconds（30 秒）"
                    + "登记一次性 state 与 ticket，303 回 Location 附带两者原值；人类令牌不进 URL。"
                    + "失败不重定向，一律返回统一错误信封",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "303", description = "授权成功：Location 为精确注册的回调，query 含一次性 ticket 与原样回传的 state")
    @ApiResponse(responseCode = "400", description = "参数缺失/空白/超长、state 字符不合法、客户端不存在或已停用、回调不精确匹配或回调非本机回环 http")
    @ApiResponse(responseCode = "401", description = "浏览器中央会话缺失、句柄失效或权威核验不通过（由拦截器拒绝，未进入本端点）")
    @ApiResponse(responseCode = "403", description = "Origin 未注册到该 SSO 客户端，或请求携带 Authorization 头被同源防护拒绝，或企业/成员关系已停用")
    @ApiResponse(responseCode = "429", description = "该中央会话的授权发起频率超过 iam.rate-limit.internal-limit 窗口配额")
    @ApiResponse(responseCode = "500", description = "查询参数整体缺失等未归类的请求绑定错误落入兜底处理器")
    @ApiResponse(responseCode = "503", description = "Redis 限流或 PostgreSQL 依赖故障（失败关闭）")
    @GetMapping({"/web-api/sso/start", "/v1/sso/authorize"})
    public ResponseEntity<Void> start(
            HttpServletRequest request,
            @Parameter(description = "目标 SSO 客户端标识（iam.sso_clients.client_id），必填，上界 128 字符")
            @RequestParam("client_id") String clientId,
            @Parameter(description = "回调地址，必填；与注册 callback_url 精确相等且限本机回环 http，上界 512 字符")
            @RequestParam("redirect_uri") String redirectUri,
            @Parameter(description = "消费方生成的一次性 state，必填；仅可打印非空白字符，上界 256，原样回传")
            @RequestParam("state") String state) {
        CurrentSession current = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        BrowserHandleRow handle = (BrowserHandleRow) request
                .getAttribute(BrowserSessionInterceptor.HANDLE_ROW_ATTRIBUTE);
        String location = authorizeService.authorize(current, handle, clientId, redirectUri,
                state, request.getHeader("Origin"));
        return ResponseEntity.status(303).location(URI.create(location)).build();
    }
}
