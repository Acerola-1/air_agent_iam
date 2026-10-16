package com.airagent.iam.webapi;

import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.token.OpaqueTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 第6组：/web-api 浏览器适配层真实链路（真实 PG iam_test + Redis DB1，无 mock）。
 * Cookie/CSRF/Origin、令牌不进 JS、即时撤销、/web-api/admin 同源路由、
 * SSO 一次性 ticket 兑换/重放/错回调，以及生产 SPA 回退与缺失资源 404。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@TestPropertySource(properties = "iam.web.static-locations=classpath:/it-ui/,classpath:/static/")
class BrowserSessionIntegrationTest {

    private static final String PASSWORD = "Test123!Pass";
    private static final String NEW_PASSWORD = "NewPass456!Word";

    private static final UUID U_PLATFORM = UUID.fromString("01932000-0000-4000-8000-000000000001");
    private static final UUID U_MEMBER = UUID.fromString("01932000-0000-4000-8000-000000000002");
    private static final UUID ROLE_PLATFORM_SUPER_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000301");
    private static final UUID ROLE_TENANT_READER = UUID.fromString(
            "01930000-0000-4000-8000-000000000312");
    private static final UUID T_A = UUID.fromString("01932000-0000-4100-8100-000000001001");
    private static final UUID M_MEMBER = UUID.fromString("01932000-0000-4300-8300-000000003001");

    private static final String SSO_CLIENT = "it-agent-local";
    private static final String SSO_SECRET = "it-sso-secret-0123456789abcdef0123456789abcdef0123456";
    private static final String SSO_CALLBACK = "http://127.0.0.1:19100/web-api/sso/callback/agent";
    private static final String SSO_AUDIENCE = "air-agent";
    private static final String SAME_ORIGIN = "http://localhost:80";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private PasswordHasher passwordHasher;
    @Autowired
    private WebCookies webCookies;
    @Autowired
    private com.airagent.iam.auth.service.SessionService sessionService;

    @Value("${spring.flyway.url}")
    private String migrateJdbcUrl;
    @Value("${spring.flyway.user}")
    private String migrateUser;
    @Value("${spring.flyway.password}")
    private String migratePassword;

    @BeforeEach
    void resetAndSeed() throws Exception {
        String hash = passwordHasher.hash(PASSWORD);
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            try (Statement st = con.createStatement()) {
                st.execute("TRUNCATE iam.internal_clients, iam.verification_refs, iam.service_tokens, "
                        + "iam.service_accounts, iam.tenants, iam.users, iam.auth_sessions, iam.audit_logs, "
                        + "iam.outbox, iam.sso_clients, iam.sso_states, iam.sso_tickets, "
                        + "iam.browser_handles, iam.bootstrap_meta CASCADE");
                String seedV2 = new String(
                        org.springframework.util.StreamUtils.copyToByteArray(
                                new org.springframework.core.io.ClassPathResource(
                                        "db/migration/V2__seed_catalog.sql").getInputStream()),
                        java.nio.charset.StandardCharsets.UTF_8);
                st.execute(seedV2);
            }
            con.setAutoCommit(false);
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                seedUser(con, U_PLATFORM, "platformAdmin", "平台超管", hash);
                seedUser(con, U_MEMBER, "memberWeb", "只读成员", hash);
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.user_roles(user_id, role_id, granted_by) VALUES (?,?,?)")) {
                    ps.setObject(1, U_PLATFORM);
                    ps.setObject(2, ROLE_PLATFORM_SUPER_ADMIN);
                    ps.setObject(3, U_PLATFORM);
                    ps.executeUpdate();
                }
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.tenants(id, code, name, created_by) VALUES (?,?,?,?)")) {
                    ps.setObject(1, T_A);
                    ps.setString(2, "TENANT-WEB-A");
                    ps.setString(3, "浏览器测试企业");
                    ps.setObject(4, U_PLATFORM);
                    ps.executeUpdate();
                }
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.tenant_memberships(id, tenant_id, user_id) VALUES (?,?,?)")) {
                    ps.setObject(1, M_MEMBER);
                    ps.setObject(2, T_A);
                    ps.setObject(3, U_MEMBER);
                    ps.executeUpdate();
                }
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by) "
                                + "VALUES (?,?,?,?)")) {
                    ps.setObject(1, T_A);
                    ps.setObject(2, M_MEMBER);
                    ps.setObject(3, ROLE_TENANT_READER);
                    ps.setObject(4, U_PLATFORM);
                    ps.executeUpdate();
                }
                con.commit();
            }
            con.setAutoCommit(true);
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.ensure_sso_client('" + SSO_CLIENT + "', 'IT 合成 Agent', '"
                        + OpaqueTokens.digest(SSO_SECRET) + "', '" + SSO_CALLBACK
                        + "', ARRAY['http://127.0.0.1:19101']::text[], '" + SSO_AUDIENCE + "')");
            }
        }
    }

    // ================================================================ CSRF / 登录

    @Test
    void csrfIssuesHttpOnlyHandleAndCsrfCookies() throws Exception {
        MvcResult result = mvc.perform(get("/web-api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();
        Jar jar = jarFrom(result);
        assertNotNull(jar.session());
        assertNotNull(jar.csrf());
        String setCookies = String.join("\n", result.getResponse().getHeaders(HttpHeaders.SET_COOKIE));
        assertTrue(setCookies.contains("HttpOnly"), "会话句柄 cookie 必须 HttpOnly");
        assertTrue(setCookies.contains("SameSite=Lax"));
        assertTrue(setCookies.contains("Path=/"));
        assertFalse(setCookies.contains("__Host-"), "本机 HTTP 使用 dev cookie 名");
        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("csrf_token"));
    }

    @Test
    void loginEnforcesOriginCsrfAndAuthorizationBan() throws Exception {
        Jar jar = openJar();
        String body = json(Map.of("account", "platformAdmin", "password", PASSWORD,
                "realm", "workforce"));

        mvc.perform(post("/web-api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/web-api/auth/login")
                        .header("Origin", "https://evil.example")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/web-api/auth/login")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, jar.csrf())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer anything")
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/web-api/auth/login")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, "wrong-csrf")
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        MvcResult ok = mvc.perform(post("/web-api/auth/login")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, jar.csrf())
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn();
        String responseBody = ok.getResponse().getContentAsString();
        assertFalse(responseBody.contains("access_token"), "浏览器登录响应不得包含 access_token");
        assertFalse(responseBody.contains("token_type"), "浏览器登录响应不得包含令牌类型字段");
        assertTrue(responseBody.contains("identity"));
        Jar bound = jarFrom(ok);
        assertFalse(bound.session().equals(jar.session()), "登录必须轮换句柄，防固定");
        assertFalse(bound.csrf().equals(jar.csrf()), "登录必须同步轮换 CSRF");
    }

    @Test
    void protectedEndpointsRequireValidBoundHandle() throws Exception {
        Jar jar = login("platformAdmin");

        MvcResult me = mvc.perform(get("/web-api/auth/me").cookie(jar.toCookies(webCookies)))
                .andExpect(status().isOk()).andReturn();
        assertTrue(me.getResponse().getContentAsString().contains("platformAdmin"));

        mvc.perform(get("/web-api/auth/me"))
                .andExpect(status().isUnauthorized());
        Jar tampered = new Jar(jar.session() + "x", jar.csrf());
        mvc.perform(get("/web-api/auth/me").cookie(tampered.toCookies(webCookies)))
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/web-api/auth/menus").cookie(jar.toCookies(webCookies)))
                .andExpect(status().isOk());
    }

    // ================================================================ /web-api/admin

    @Test
    void webAdminRoutesUseSameBackendAuthorization() throws Exception {
        Jar platform = login("platformAdmin");
        mvc.perform(get("/web-api/admin/users").cookie(platform.toCookies(webCookies)))
                .andExpect(status().isOk());
        mvc.perform(get("/v1/admin/users")
                        .header(HttpHeaders.AUTHORIZATION,
                                "Bearer " + sessionService.login(
                                        new com.airagent.iam.auth.dto.LoginDTO(
                                                "platformAdmin", PASSWORD, "workforce",
                                                "iam-admin")).accessToken()))
                .andExpect(status().isOk());

        Jar member = login("memberWeb");
        mvc.perform(get("/web-api/admin/users").cookie(member.toCookies(webCookies)))
                .andExpect(status().isForbidden());
    }

    // ================================================================ 即时撤销 / 登出

    @Test
    void logoutAndAdminPasswordRevocationTakeEffectImmediately() throws Exception {
        Jar jar = login("memberWeb");
        mvc.perform(get("/web-api/auth/me").cookie(jar.toCookies(webCookies)))
                .andExpect(status().isOk());

        Jar admin = login("platformAdmin");
        String resetBody = json(java.util.Map.of(
                "new_password", "ResetPass789!", "auth_revision", 0));
        mvc.perform(post("/web-api/admin/users/" + U_MEMBER + "/password")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, admin.csrf())
                        .cookie(admin.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(resetBody))
                .andExpect(status().isNoContent());
        mvc.perform(get("/web-api/auth/me").cookie(jar.toCookies(webCookies)))
                .andExpect(status().isUnauthorized());

        Jar other = login("memberWeb", "ResetPass789!");
        mvc.perform(post("/web-api/auth/logout")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, other.csrf())
                        .cookie(other.toCookies(webCookies)))
                .andExpect(status().isNoContent());
        mvc.perform(get("/web-api/auth/me").cookie(other.toCookies(webCookies)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void oldCsrfRejectedAfterRotationAndSwitchTenantUpdatesContext() throws Exception {
        Jar jar = login("memberWeb");
        String body = json(Map.of());
        mvc.perform(post("/web-api/auth/switch-tenant")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, "stale")
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        String switchBody = json(java.util.Map.of(
                "tenant_id", T_A.toString(), "expected_ctx_version", 1));
        MvcResult switched = mvc.perform(post("/web-api/auth/switch-tenant")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, jar.csrf())
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(switchBody))
                .andExpect(status().isOk()).andReturn();
        assertTrue(switched.getResponse().getContentAsString().contains(T_A.toString()));
        assertTrue(switched.getResponse().getContentAsString().contains("context_usable"));
    }

    // ================================================================ SSO

    @Test
    void ssoStartRequiresBrowserSessionAndExactCallback() throws Exception {
        Jar jar = login("platformAdmin");
        mvc.perform(get("/web-api/sso/start")
                        .param("client_id", SSO_CLIENT)
                        .param("redirect_uri", SSO_CALLBACK)
                        .param("state", "state-abc-123"))
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/web-api/sso/start")
                        .cookie(jar.toCookies(webCookies))
                        .param("client_id", SSO_CLIENT)
                        .param("redirect_uri", "http://127.0.0.1:19100/other-callback")
                        .param("state", "state-abc-123"))
                .andExpect(status().isBadRequest());

        MvcResult start = mvc.perform(get("/web-api/sso/start")
                        .cookie(jar.toCookies(webCookies))
                        .param("client_id", SSO_CLIENT)
                        .param("redirect_uri", SSO_CALLBACK)
                        .param("state", "state-abc-123"))
                .andExpect(status().isSeeOther()).andReturn();
        URI location = URI.create(start.getResponse().getRedirectedUrl());
        assertNotNull(location.getRawQuery());
        assertTrue(location.toString().startsWith(SSO_CALLBACK + "?"));
    }

    @Test
    void ssoExchangeMintsScopedSessionAndRejectsReplayWrongCallbackBadSecret() throws Exception {
        Jar jar = login("platformAdmin");
        String state = "exchange-state-456";
        String firstTicket = startTicket(jar, SSO_CALLBACK, state);

        String wrongCallback = json(java.util.Map.of(
                "ticket", firstTicket, "redirect_uri", "http://127.0.0.1:19100/wrong",
                "state", state));
        mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, SSO_SECRET))
                        .contentType(MediaType.APPLICATION_JSON).content(wrongCallback))
                .andExpect(status().isBadRequest());

        mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, "bad-secret-000000000000000000000000000000"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(exchangeBody(firstTicket, SSO_CALLBACK, state)))
                .andExpect(status().isUnauthorized());

        MvcResult exchanged = mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, SSO_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(exchangeBody(firstTicket, SSO_CALLBACK, state)))
                .andExpect(status().isOk()).andReturn();
        String exchangeJson = exchanged.getResponse().getContentAsString();
        assertTrue(exchangeJson.contains("access_token"));
        assertTrue(exchangeJson.contains("\"audience\":\"" + SSO_AUDIENCE + "\""));
        String appToken = mapper.readTree(exchangeJson).path("access_token").asText();

        mvc.perform(get("/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + appToken))
                .andExpect(status().isOk());

        mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, SSO_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(exchangeBody(firstTicket, SSO_CALLBACK, state)))
                .andExpect(status().isUnauthorized());

        String secondTicket = startTicket(jar, SSO_CALLBACK, "another-state-789");
        mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, SSO_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(exchangeBody(secondTicket, SSO_CALLBACK, state)))
                .andExpect(status().isUnauthorized());
    }

    // ================================================================ SPA 回退 / 404

    @Test
    void centralContextAndLogoutImmediatelyApplyToSsoApplication() throws Exception {
        Jar jar = login("memberWeb");
        String state = "shared-central-state";
        String ticket = startTicket(jar, SSO_CALLBACK, state);
        MvcResult exchange = mvc.perform(post("/v1/internal/sso/exchange")
                        .header(HttpHeaders.AUTHORIZATION, basic(SSO_CLIENT, SSO_SECRET))
                        .contentType(MediaType.APPLICATION_JSON).content(exchangeBody(ticket, SSO_CALLBACK, state)))
                .andExpect(status().isOk()).andReturn();
        String appToken = mapper.readTree(exchange.getResponse().getContentAsString()).path("access_token").asText();
        mvc.perform(post("/web-api/auth/switch-tenant").cookie(jar.toCookies(webCookies))
                        .header(HttpHeaders.ORIGIN, SAME_ORIGIN).header("X-CSRF-Token", jar.csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("tenant_id", T_A.toString(), "expected_ctx_version", 1))))
                .andExpect(status().isOk());
        MvcResult app = mvc.perform(get("/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + appToken))
                .andExpect(status().isOk()).andReturn();
        var identity = mapper.readTree(app.getResponse().getContentAsString());
        assertEquals(T_A.toString(), identity.path("current_tenant").path("id").asText());
        assertEquals(2, identity.path("context_version").asInt());
        mvc.perform(post("/web-api/auth/logout").cookie(jar.toCookies(webCookies))
                        .header(HttpHeaders.ORIGIN, SAME_ORIGIN).header("X-CSRF-Token", jar.csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + appToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void spaDeepLinkServesIndexButUnknownApiAndMissingAssetStayJson404() throws Exception {
        MvcResult deep = mvc.perform(get("/admin/platform/users")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
                .andExpect(status().isOk()).andReturn();
        assertTrue(deep.getResponse().getContentAsString().contains("it-spa-marker"));

        MvcResult missingAsset = mvc.perform(get("/assets/index-nope.js"))
                .andExpect(status().isNotFound()).andReturn();
        assertTrue(missingAsset.getResponse().getContentAsString().contains("not_found"));
        assertFalse(missingAsset.getResponse().getContentAsString().contains("it-spa-marker"));

        MvcResult unknownApi = mvc.perform(get("/v1/admin/nope"))
                .andExpect(status().isNotFound()).andReturn();
        assertTrue(unknownApi.getResponse().getContentAsString().contains("not_found"));

        Jar jar = login("platformAdmin");
        MvcResult apiNotHtml = mvc.perform(get("/web-api/auth/missing")
                        .cookie(jar.toCookies(webCookies)))
                .andExpect(status().isNotFound()).andReturn();
        assertFalse(apiNotHtml.getResponse().getContentAsString().contains("it-spa-marker"));
    }

    // ================================================================ helpers

    private String startTicket(Jar jar, String callback, String state) throws Exception {
        MvcResult start = mvc.perform(get("/web-api/sso/start")
                        .cookie(jar.toCookies(webCookies))
                        .param("client_id", SSO_CLIENT)
                        .param("redirect_uri", callback)
                        .param("state", state))
                .andExpect(status().isSeeOther()).andReturn();
        String query = URI.create(start.getResponse().getRedirectedUrl()).getRawQuery();
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if ("ticket".equals(kv[0])) {
                return java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("303 Location 缺少 ticket");
    }

    private String exchangeBody(String ticket, String callback, String state) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("ticket", ticket);
        payload.put("redirect_uri", callback);
        payload.put("state", state);
        return mapper.writeValueAsString(payload);
    }

    private Jar openJar() throws Exception {
        MvcResult result = mvc.perform(get("/web-api/auth/csrf"))
                .andExpect(status().isOk()).andReturn();
        return jarFrom(result);
    }

    private Jar login(String account) throws Exception {
        return login(account, PASSWORD);
    }

    private Jar login(String account, String password) throws Exception {
        Jar jar = openJar();
        String body = json(java.util.Map.of(
                "account", account, "password", password, "realm", "workforce"));
        MvcResult result = mvc.perform(post("/web-api/auth/login")
                        .header("Origin", SAME_ORIGIN)
                        .header(WebCookies.CSRF_HEADER, jar.csrf())
                        .cookie(jar.toCookies(webCookies))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andReturn();
        return jarFrom(result);
    }

    private String json(Map<String, Object> payload) throws Exception {
        return mapper.writeValueAsString(payload);
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static void seedUser(Connection con, UUID id, String account, String displayName,
                                 String hash) throws Exception {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setString(2, account);
            ps.setString(3, displayName);
            ps.setString(4, hash);
            ps.executeUpdate();
        }
    }

    private Jar jarFrom(MvcResult result) {
        String session = null;
        String csrf = null;
        for (String header : result.getResponse().getHeaders(HttpHeaders.SET_COOKIE)) {
            String[] parts = header.split(";", 2)[0].split("=", 2);
            if (parts.length != 2) {
                continue;
            }
            if (webCookies.sessionCookieName().equals(parts[0])) {
                session = parts[1];
            } else if (webCookies.csrfCookieName().equals(parts[0])) {
                csrf = parts[1];
            }
        }
        return new Jar(session, csrf);
    }

    private record Jar(String session, String csrf) {
        jakarta.servlet.http.Cookie[] toCookies(WebCookies cookies) {
            return new jakarta.servlet.http.Cookie[]{
                    new jakarta.servlet.http.Cookie(cookies.sessionCookieName(), session),
                    new jakarta.servlet.http.Cookie(cookies.csrfCookieName(), csrf)
            };
        }
    }
}
