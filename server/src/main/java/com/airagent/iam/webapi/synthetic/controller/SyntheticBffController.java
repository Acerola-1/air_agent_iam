package com.airagent.iam.webapi.synthetic.controller;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.synthetic.SyntheticSessionStore;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * 自有合成应用 BFF（Controller 层，仅本机验收，可用 {@code iam.web.synthetic-consumer-enabled=false} 关闭）。
 *
 * <p>定位：这不是 IAM 自身的会话面，而是<em>模拟一个外部消费者应用</em>的后端聚合层（BFF），
 * 端到端演示跨端 SSO 的真实语义——浏览器先到达 BFF 起始端点，BFF 生成一次性 {@code state}
 * 并 303 跳中央 {@code /web-api/sso/start}；中央 303 回到精确注册的回调并附带一次性 {@code ticket}；
 * BFF 在服务端用 Basic 凭据兑换应用令牌，浏览器侧自始至终只有 BFF 自己的 HttpOnly 会话 Cookie，
 * 人类令牌既不进浏览器也不出 BFF 进程（存于 {@link SyntheticSessionStore}）。
 *
 * <p>派生会话与传播：兑换出的应用会话由 IAM 数据库以 {@code central_session_id} 关联到浏览器中央
 * 权威会话；中央的<em>退出、切企业、续期</em>经 {@code auth_sessions_synchronize_central} 触发器
 * 原子传播到该派生子会话。因此 {@link #me} 每次实时回源中央 {@code /v1/auth/me}——一旦中央已退出
 * 或过期，中央返回非 2xx，BFF 立即清理本地会话并回 401，等价于"中央退出后旧 Cookie 失效"。
 *
 * <p>与平台鉴权面的区别：本类端点<em>不</em>使用平台 {@code browserCookie} 方案，
 * 也不被 {@code BrowserSessionInterceptor} 挂载（其路径不匹配 {@code /web-api/sso/start}）；
 * 写侧只受 {@code CsrfOriginInterceptor} 的 {@code Authorization} 头拒绝约束（均为 GET 安全方法）。
 * BFF 自身的 Cookie 为 {@code air_iam_demo_{key}} 与 {@code air_iam_demo_{key}_state}，
 * 作用域限定在 {@code /web-api/sso/callback/{key}}，本机演示固定 {@code Secure=false}、
 * {@code HttpOnly=true}、{@code SameSite=Lax}。
 *
 * <p>协作关系：{@link IamProperties.Sso} 提供注册客户端（id/secret/精确回调/受众），
 * {@link IamProperties.Web#centralBaseUrl()} 为中央基址；兑换走中央
 * {@code /v1/internal/sso/exchange}（内部客户端面，Basic 认证）。
 *
 * @author Acerola
 */
@Tag(name = "合成消费者 BFF", description = "本机验收用的外部应用 BFF 演示：303 中央授权、一次性 ticket 服务端 Basic 兑换、"
        + "浏览器仅持有 BFF 自己的 HttpOnly 会话 Cookie；派生子会话随中央退出/切企业/续期同步，中央退出后旧 Cookie 回 401")
@RestController
@ConditionalOnProperty(name = "iam.web.synthetic-consumer-enabled",
        havingValue = "true", matchIfMissing = true)
public class SyntheticBffController {

    /** BFF 侧 {@code state} Cookie 的存活时长；覆盖一次授权往返即可，10 分钟上界。 */
    private static final Duration STATE_TTL = Duration.ofMinutes(10);

    /** iam.* 配置（SSO 客户端注册表）。 */
    private final IamProperties props;
    /** BFF 派生会话存储。 */
    private final SyntheticSessionStore store;
    /** JSON 读写。 */
    private final ObjectMapper mapper;
    /** 回源中央 IAM 的 HTTP 客户端。 */
    private final RestClient http;

    /**
     * 构造合成 BFF。
     *
     * @param props  {@code iam.*} 配置；取中央基址与 SSO 客户端注册表
     * @param store  BFF 服务端会话存储（进程内）
     * @param mapper JSON 处理器；序列化兑换请求体、解析兑换响应
     */
    public SyntheticBffController(IamProperties props, SyntheticSessionStore store,
                                  ObjectMapper mapper) {
        this.props = props;
        this.store = store;
        this.mapper = mapper;
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
                java.net.http.HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .build());
        factory.setReadTimeout(Duration.ofSeconds(5));
        this.http = RestClient.builder()
                .baseUrl(props.web().centralBaseUrl())
                .requestFactory(factory)
                .build();
    }

    /**
     * 授权起始：生成随机 {@code state} 写入 BFF 自身作用域的 HttpOnly Cookie，303 跳中央授权入口。
     *
     * @param key      合成客户端 key
     * @param response 当前响应；写 {@code state} Cookie 与 {@code Location} 303
     * @throws ApiException 404 客户端未配置或缺少密钥
     * @throws Exception 响应写出/兑换过程中的受检异常不在方法内消化，交由容器与全局异常处理器兜底
     */
    @Operation(summary = "BFF 授权起始（303 跳中央）",
            description = "公开：浏览器导航入口，无平台会话 Cookie。BFF 生成一次性 state 存于自身 HttpOnly Cookie，"
                    + "随后 303 到中央 /web-api/sso/start?client_id&redirect_uri&state；redirect_uri 为精确注册回调",
            security = {})
    @ApiResponse(responseCode = "303", description = "重定向到中央授权入口")
    @ApiResponse(responseCode = "404", description = "合成客户端未配置或缺少密钥")
    @GetMapping("/web-api/sso/callback/{key}/login")
    public void loginStart(@Parameter(description = "合成客户端 key，对应 iam.sso.clients 的键")
                           @PathVariable String key, HttpServletResponse response) throws Exception {
        IamProperties.SsoClient client = client(key);
        String state = OpaqueTokens.newRawToken();
        response.addHeader(HttpHeaders.SET_COOKIE, stateCookie(key, state, STATE_TTL).toString());
        String location = props.web().centralBaseUrl() + "/web-api/sso/start?client_id="
                + enc(client.id()) + "&redirect_uri=" + enc(client.callbackUrl())
                + "&state=" + enc(state);
        response.setStatus(HttpStatus.SEE_OTHER.value());
        response.setHeader(HttpHeaders.LOCATION, location);
    }

    /**
     * 中央回调：常量时间校验 {@code state}，服务端兑换一次性 {@code ticket}，再 303 到不含 ticket 的演示页。
     *
     * <p>成功时签发 BFF 自己的会话 Cookie；失败或重放时以 {@code ?error=} 回传原因码，票据与 state
     * 均不落到最终页面 URL。无论成败都即刻失效 {@code state} Cookie（一次性）。
     *
     * @param key      合成客户端 key
     * @param request  当前请求；读取 {@code state} Cookie
     * @param response 当前响应；写 BFF 会话 Cookie、清 {@code state} Cookie、303 {@code Location}
     * @param ticket   中央回调附带的一次性票据；缺失或空白记 {@code missing_grant}
     * @param state    中央回调附带的 state；与 Cookie 常量时间不等记 {@code state_mismatch}
     * @throws ApiException 503 兑换处理出现非网络类异常；404 客户端未配置
     * @throws Exception 响应写出/兑换过程中的受检异常不在方法内消化，交由容器与全局异常处理器兜底
     */
    @Operation(summary = "BFF 授权回调（服务端兑换 + 303）",
            description = "公开：仅收一次性 ticket 与 state。state 与 BFF 自身 HttpOnly Cookie 常量时间比对；"
                    + "通过后服务端以 Basic 凭据调用中央 /v1/internal/sso/exchange 兑换应用令牌，令牌只存进程内，"
                    + "浏览器得到的是 BFF 自己的会话 Cookie。最终 303 到 /demo/{key}/，ticket 不出现在页面 URL",
            security = {})
    @ApiResponse(responseCode = "303", description = "重定向到演示页；失败以 ?error= 携带原因码")
    @ApiResponse(responseCode = "404", description = "合成客户端未配置")
    @ApiResponse(responseCode = "503", description = "兑换处理出现非网络类异常")
    @GetMapping("/web-api/sso/callback/{key}")
    public void callback(@Parameter(description = "合成客户端 key")
                         @PathVariable String key,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         @org.springframework.web.bind.annotation.RequestParam(value = "ticket", required = false)
                         String ticket,
                         @org.springframework.web.bind.annotation.RequestParam(value = "state", required = false)
                         String state) throws Exception {
        IamProperties.SsoClient client = client(key);
        String expectedState = cookie(request, stateCookieName(key));
        String error;
        if (ticket == null || ticket.isBlank() || state == null || state.isBlank()) {
            error = "missing_grant";
        } else if (expectedState == null
                || !constantTimeEquals(state, expectedState)) {
            error = "state_mismatch";
        } else {
            error = exchangeAndBind(key, client, ticket, state, response);
        }
        response.addHeader(HttpHeaders.SET_COOKIE, stateCookie(key, "", Duration.ZERO).toString());
        response.setStatus(HttpStatus.SEE_OTHER.value());
        response.setHeader(HttpHeaders.LOCATION, "/demo/" + key + "/?error=" + enc(error == null ? "" : error));
    }

    /**
     * 实时身份：用 BFF 保存的应用令牌回源中央 {@code /v1/auth/me}，浏览器只拿安全身份 JSON。
     *
     * <p>中央返回非 2xx（典型为派生子会话因中央退出/过期被撤销）时，删除本地 BFF 会话、
     * 失效其 Cookie 并回 401——这正是"中央权威变更即时传播到应用侧"的可观测点。
     *
     * @param key      合成客户端 key
     * @param request  当前请求；读取 BFF 会话 Cookie
     * @param response 当前响应；写身份 JSON 或 401，统一 {@code Cache-Control: no-store}
     * @throws Exception 响应写出/兑换过程中的受检异常不在方法内消化，交由容器与全局异常处理器兜底
     */
    @Operation(summary = "BFF 拉取实时身份（回源中央 /v1/auth/me）",
            description = "使用 BFF 自身的 HttpOnly 会话 Cookie（非平台 browserCookie）鉴权：无本地会话回 401；"
                    + "以服务端保存的应用令牌调用中央 /v1/auth/me，中央非 2xx（如中央退出使派生子会话失效）则清会话回 401",
            security = {})
    @ApiResponse(responseCode = "200", description = "透传中央返回的安全身份 JSON")
    @ApiResponse(responseCode = "401", description = "BFF 会话不存在/已失效，或中央会话已失效")
    @GetMapping(value = "/web-api/sso/callback/{key}/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public void me(@Parameter(description = "合成客户端 key")
                   @PathVariable String key, HttpServletRequest request,
                   HttpServletResponse response) throws Exception {
        SyntheticSessionStore.Entry entry = store.get(cookie(request, bffCookieName(key)));
        if (entry == null) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "合成应用会话不存在或已失效");
            return;
        }
        byte[] identityBody;
        try {
            identityBody = http.get()
                    .uri("/v1/auth/me")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + entry.accessToken())
                    .retrieve()
                    .body(byte[].class);
        } catch (org.springframework.web.client.RestClientException e) {
            store.remove(cookie(request, bffCookieName(key)));
            response.addHeader(HttpHeaders.SET_COOKIE, bffCookie(key, "", Duration.ZERO).toString());
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "中央会话已失效");
            return;
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getOutputStream().write(identityBody == null ? new byte[0] : identityBody);
    }

    /**
     * BFF 登出：删除进程内会话并失效其 Cookie，303 回演示页。
     *
     * <p>只清理 BFF 侧会话，<em>不</em>等价于中央退出；中央会话与派生子会话的撤销由中央侧
     * 生命周期与触发器负责。
     *
     * @param key      合成客户端 key
     * @param request  当前请求；读取 BFF 会话 Cookie
     * @param response 当前响应；清 Cookie 并 303
     */
    @Operation(summary = "BFF 登出（清本地会话 + 303）",
            description = "公开：删除 BFF 进程内会话并失效其 HttpOnly Cookie，303 回 /demo/{key}/；不影响中央会话本身",
            security = {})
    @ApiResponse(responseCode = "303", description = "重定向回演示页")
    @GetMapping("/web-api/sso/callback/{key}/logout")
    public void bffLogout(@Parameter(description = "合成客户端 key")
                          @PathVariable String key, HttpServletRequest request,
                          HttpServletResponse response) {
        String bffSessionId = cookie(request, bffCookieName(key));
        store.remove(bffSessionId);
        response.addHeader(HttpHeaders.SET_COOKIE, bffCookie(key, "", Duration.ZERO).toString());
        response.setStatus(HttpStatus.SEE_OTHER.value());
        response.setHeader(HttpHeaders.LOCATION, "/demo/" + key + "/");
    }

    // ------------------------------------------------------------- 内部

    /**
     * 服务端兑换并绑定 BFF 会话：向中央 {@code /v1/internal/sso/exchange} 发起 Basic 兑换，
     * 成功后写进程内会话与 BFF Cookie。
     *
     * @param key      合成客户端 key（用于 Cookie 命名与存储条目）
     * @param client   已解析的合成客户端（id/secret/精确回调）
     * @param ticket   中央一次性票据
     * @param state    已校验通过的 state（随请求体一并提交给兑换函数）
     * @param response 当前响应；兑换成功时写 BFF 会话 Cookie
     * @return 失败原因码；成功返回 {@code null}
     */
    private String exchangeAndBind(String key, IamProperties.SsoClient client,
                                   String ticket, String state, HttpServletResponse response) {
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("ticket", ticket);
            payload.put("redirect_uri", client.callbackUrl());
            payload.put("state", state);
            String basic = Base64.getEncoder().encodeToString(
                    (client.id() + ":" + client.secret()).getBytes(StandardCharsets.UTF_8));
            String body = http.post()
                    .uri("/v1/internal/sso/exchange")
                    .header(HttpHeaders.AUTHORIZATION, "Basic " + basic)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(mapper.writeValueAsString(payload))
                    .retrieve()
                    .body(String.class);
            JsonNode node = mapper.readTree(body == null ? "{}" : body);
            String accessToken = node.path("access_token").asText(null);
            JsonNode identity = node.path("identity");
            if (accessToken == null || accessToken.isBlank() || identity.isMissingNode()) {
                return "exchange_payload_invalid";
            }
            long expiresIn = node.path("expires_in").asLong(3600);
            String bffSessionId = OpaqueTokens.newRawToken();
            store.put(bffSessionId, new SyntheticSessionStore.Entry(
                    key, accessToken, identity.toString(),
                    Instant.now().plusSeconds(Math.max(60, expiresIn - 30))));
            response.addHeader(HttpHeaders.SET_COOKIE,
                    bffCookie(key, bffSessionId, Duration.ofSeconds(Math.max(60, expiresIn - 30)))
                            .toString());
            return null;
        } catch (org.springframework.web.client.RestClientException e) {
            return "exchange_rejected";
        } catch (Exception e) {
            throw ApiException.dependencyUnavailable("合成 BFF 兑换处理失败");
        }
    }

    /**
     * 解析合成客户端配置，缺失或未配密钥即拒绝。
     *
     * @param key 客户端 key
     * @return 配置完整的 {@link IamProperties.SsoClient}
     * @throws ApiException 404 未配置 clients、无该 key、或 id/secret 缺失/空白
     */
    private IamProperties.SsoClient client(String key) {
        if (props.sso() == null || props.sso().clients() == null) {
            throw ApiException.notFound("合成客户端未配置");
        }
        IamProperties.SsoClient client = props.sso().clients().get(key);
        if (client == null || client.id() == null || client.secret() == null
                || client.secret().isBlank()) {
            throw ApiException.notFound("合成客户端未配置或缺少密钥");
        }
        return client;
    }

    /**
     * 装配 {@code state} Cookie：HttpOnly、作用域限定到本客户端回调路径、本机演示 {@code Secure=false}。
     *
     * @param key    客户端 key（决定 Cookie 名与路径）
     * @param value  state 值；清空时传空串
     * @param maxAge 存活时长；{@link Duration#ZERO} 即刻失效
     * @return 用于写 {@code Set-Cookie} 的 {@link ResponseCookie}
     */
    private ResponseCookie stateCookie(String key, String value, Duration maxAge) {
        return ResponseCookie.from(stateCookieName(key), value)
                .httpOnly(true).secure(false).path("/web-api/sso/callback/" + key)
                .sameSite("Lax").maxAge(maxAge).build();
    }

    /**
     * 装配 BFF 会话 Cookie：HttpOnly、作用域限定到本客户端回调路径、本机演示 {@code Secure=false}。
     *
     * @param key    客户端 key
     * @param value  BFF 会话标识；清空时传空串
     * @param maxAge 存活时长；{@link Duration#ZERO} 即刻失效
     * @return 用于写 {@code Set-Cookie} 的 {@link ResponseCookie}
     */
    private ResponseCookie bffCookie(String key, String value, Duration maxAge) {
        return ResponseCookie.from(bffCookieName(key), value)
                .httpOnly(true).secure(false).path("/web-api/sso/callback/" + key)
                .sameSite("Lax").maxAge(maxAge).build();
    }

    /**
     * {@code state} Cookie 名：{@code air_iam_demo_{key}_state}，按客户端 key 隔离。
     *
     * @param key 客户端 key
     * @return Cookie 名
     */
    private String stateCookieName(String key) {
        return "air_iam_demo_" + key + "_state";
    }

    /**
     * BFF 会话 Cookie 名：{@code air_iam_demo_{key}}，按客户端 key 隔离。
     *
     * @param key 客户端 key
     * @return Cookie 名
     */
    private String bffCookieName(String key) {
        return "air_iam_demo_" + key;
    }

    /**
     * 从请求 Cookie 数组按<em>精确名</em>读取值（允许空白值原样返回，由调用方判定）。
     *
     * @param request 当前请求；{@code getCookies()} 可能为 {@code null}
     * @param name    目标 Cookie 名
     * @return 匹配到的 Cookie 值；无同名 Cookie 返回 {@code null}
     */
    private String cookie(HttpServletRequest request, String name) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * URL 编码（UTF-8），用于安全拼接跳转 {@code Location} 与回传 {@code error} 查询参数。
     *
     * @param value 待编码文本
     * @return {@code application/x-www-form-urlencoded} 风格编码结果
     */
    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * UTF-8 字节级常量时间比较，抵御 {@code state} 时序侧信道。
     *
     * @param a 回调携带的 state
     * @param b BFF Cookie 中记录的期望 state
     * @return 字节完全相等返回 {@code true}
     */
    private static boolean constantTimeEquals(String a, String b) {
        return java.security.MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
