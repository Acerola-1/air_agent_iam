package com.airagent.iam.security.internal;

import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * C12 限流：低阈值独立上下文，验证登录按主体、内部端点按客户端的固定窗口 429。
 */
@SpringBootTest
@ActiveProfiles("it")
@TestPropertySource(properties = {
        "iam.rate-limit.login-limit=2",
        "iam.rate-limit.internal-limit=3"
})
class RateLimitIntegrationTest {

    private static final String PASSWORD = "Test123!Pass";
    private final UUID userId = UUID.randomUUID();
    // 主体/客户端每轮唯一：固定窗口计数器在 Redis 中跨复跑存活，避免同分钟复跑被历史计数污染
    private final String account = "rluser-" + UUID.randomUUID().toString().substring(0, 8);
    private final String rlClient = "it-rate-client-" + UUID.randomUUID().toString().substring(0, 8);
    private static final String RL_SECRET = "rate-secret-0123456789abcdef0123456789";

    @Autowired
    private SessionService sessionService;
    @Autowired
    private PasswordHasher passwordHasher;
    @Autowired
    private InternalClientInterceptor interceptor;

    @Value("${spring.flyway.url}")
    private String migrateJdbcUrl;
    @Value("${spring.flyway.user}")
    private String migrateUser;
    @Value("${spring.flyway.password}")
    private String migratePassword;

    @BeforeEach
    void seed() throws Exception {
        String hash = passwordHasher.hash(PASSWORD);
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            try (Statement st = con.createStatement()) {
                st.execute("TRUNCATE iam.internal_clients, iam.verification_refs, iam.service_tokens, "
                        + "iam.service_accounts, iam.resource_catalog, iam.tenants, iam.users, iam.auth_sessions, iam.audit_logs, "
                        + "iam.outbox, iam.sso_clients, iam.browser_handles, iam.bootstrap_meta CASCADE");
                String seedV2 = new String(
                        org.springframework.util.StreamUtils.copyToByteArray(
                                new org.springframework.core.io.ClassPathResource(
                                        "db/migration/V2__seed_catalog.sql").getInputStream()),
                        java.nio.charset.StandardCharsets.UTF_8);
                con.setAutoCommit(false);
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                st.execute("INSERT INTO iam.resource_catalog(code,name_zh,sort,status,kind,parent_code) VALUES ('knowledge:lib:air','空气知识库',10,'active','leaf','knowledge') ON CONFLICT (code) DO NOTHING");
                st.execute(seedV2);
                st.execute("INSERT INTO iam.permissions(id,code,name_zh,scope,grantable_to_tenants,sort) VALUES "
                        + "('01930000-0000-4000-8000-000000000211','tenant:resource:grant','企业资源授权管理','tenant',true,211) ON CONFLICT DO NOTHING");
                st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT r.id,p.id FROM iam.roles r "
                        + "JOIN iam.permissions p ON p.code='tenant:resource:grant' WHERE r.code='tenant_admin' AND r.tenant_id IS NULL ON CONFLICT DO NOTHING");
                con.commit();
            }
            con.setAutoCommit(false);
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
                ps.setObject(1, userId);
                ps.setString(2, account);
                ps.setString(3, "限流用户");
                ps.setString(4, hash);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences) "
                            + "VALUES (?, ?, ?, ?::text[], ?::text[])")) {
                ps.setString(1, rlClient);
                ps.setString(2, rlClient);
                ps.setString(3, OpaqueTokens.digest(RL_SECRET));
                ps.setObject(4, con.createArrayOf("text",
                        new String[]{"identity:introspect"}));
                ps.setObject(5, con.createArrayOf("text",
                        new String[]{"langgraph-runtime"}));
                ps.executeUpdate();
            }
            con.commit();
            con.close();
        }
    }

    @Test
    void loginBurstBeyondLimitReturns429() {
        sessionService.login(new LoginDTO(account, PASSWORD, "workforce", "iam-admin"));
        sessionService.login(new LoginDTO(account, PASSWORD, "workforce", "iam-admin"));
        ApiException ex = assertThrows(ApiException.class, () -> sessionService
                .login(new LoginDTO(account, PASSWORD, "workforce", "iam-admin")));
        assertEquals(429, ex.status());
        assertEquals("rate_limited", ex.code());
    }

    @Test
    void internalBurstBeyondLimitReturns429() {
        for (int i = 1; i <= 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST",
                    "/v1/internal/identity/introspect");
            request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    (rlClient + ":" + RL_SECRET).getBytes(StandardCharsets.UTF_8)));
            interceptor.preHandle(request, new MockHttpServletResponse(), new Object());
        }
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                "/v1/internal/identity/introspect");
        request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                (rlClient + ":" + RL_SECRET).getBytes(StandardCharsets.UTF_8)));
        ApiException ex = assertThrows(ApiException.class, () ->
                interceptor.preHandle(request, new MockHttpServletResponse(), new Object()));
        assertEquals(429, ex.status());
    }
}
