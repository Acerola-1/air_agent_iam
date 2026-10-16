package com.airagent.iam.webapi.synthetic.controller;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.synthetic.SyntheticSessionStore;
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
 * 自有合成应用 BFF（仅本机验收，生产关闭）：演示真实跨端 SSO——
 * 起始 303 中央授权、回调只收一次性 ticket、服务端 Basic 兑换应用令牌，
 * 浏览器侧只有 BFF 自己的 HttpOnly 会话 cookie。
 */
@RestController
@ConditionalOnProperty(name = "iam.web.synthetic-consumer-enabled",
        havingValue = "true", matchIfMissing = true)
public class SyntheticBffController {

    private static final Duration STATE_TTL = Duration.ofMinutes(10);

    private final IamProperties props;
    private final SyntheticSessionStore store;
    private final ObjectMapper mapper;
    private final RestClient http;

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

    /** BFF 生成 state（写入仅自身路径可读的 HttpOnly cookie）后 303 到中央 /sso/start。 */
    @GetMapping("/web-api/sso/callback/{key}/login")
    public void loginStart(@PathVariable String key, HttpServletResponse response) throws Exception {
        IamProperties.SsoClient client = client(key);
        String state = OpaqueTokens.newRawToken();
        response.addHeader(HttpHeaders.SET_COOKIE, stateCookie(key, state, STATE_TTL).toString());
        String location = props.web().centralBaseUrl() + "/web-api/sso/start?client_id="
                + enc(client.id()) + "&redirect_uri=" + enc(client.callbackUrl())
                + "&state=" + enc(state);
        response.setStatus(HttpStatus.SEE_OTHER.value());
        response.setHeader(HttpHeaders.LOCATION, location);
    }

    /** 中央 303 回到精确注册回调：校验 state 后服务端兑换，再 303 到无 ticket 的白名单页面。 */
    @GetMapping("/web-api/sso/callback/{key}")
    public void callback(@PathVariable String key,
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

    /** BFF 用服务端保存的应用令牌实时调用中央 /v1/auth/me，浏览器只拿到安全身份 JSON。 */
    @GetMapping(value = "/web-api/sso/callback/{key}/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public void me(@PathVariable String key, HttpServletRequest request,
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

    @GetMapping("/web-api/sso/callback/{key}/logout")
    public void bffLogout(@PathVariable String key, HttpServletRequest request,
                          HttpServletResponse response) {
        String bffSessionId = cookie(request, bffCookieName(key));
        store.remove(bffSessionId);
        response.addHeader(HttpHeaders.SET_COOKIE, bffCookie(key, "", Duration.ZERO).toString());
        response.setStatus(HttpStatus.SEE_OTHER.value());
        response.setHeader(HttpHeaders.LOCATION, "/demo/" + key + "/");
    }

    // ------------------------------------------------------------- 内部

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

    private ResponseCookie stateCookie(String key, String value, Duration maxAge) {
        return ResponseCookie.from(stateCookieName(key), value)
                .httpOnly(true).secure(false).path("/web-api/sso/callback/" + key)
                .sameSite("Lax").maxAge(maxAge).build();
    }

    private ResponseCookie bffCookie(String key, String value, Duration maxAge) {
        return ResponseCookie.from(bffCookieName(key), value)
                .httpOnly(true).secure(false).path("/web-api/sso/callback/" + key)
                .sameSite("Lax").maxAge(maxAge).build();
    }

    private String stateCookieName(String key) {
        return "air_iam_demo_" + key + "_state";
    }

    private String bffCookieName(String key) {
        return "air_iam_demo_" + key;
    }

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

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return java.security.MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
