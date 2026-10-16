package com.airagent.iam.internal;

import com.airagent.iam.internal.service.RuntimeTicketService;

import com.airagent.iam.internal.service.IntrospectionService;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.internal.dto.ExecutionContextRefDTO;
import com.airagent.iam.internal.dto.ExpectedContextDTO;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.internal.vo.RecheckActiveVO;
import com.airagent.iam.internal.vo.RecheckInactiveVO;
import com.airagent.iam.internal.dto.RevisionsDTO;
import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.internal.vo.InactiveIntrospectionVO;
import com.airagent.iam.internal.vo.ServiceIdentityVO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.security.internal.InternalClientAuthenticator;
import com.airagent.iam.security.internal.InternalClientInterceptor;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.rt.RtV1Codec;
import com.airagent.iam.security.rt.RtV1VerifyResult;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.serviceaccount.service.ServiceAccountService;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;
import com.airagent.iam.web.error.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C12/C13/C03/C15：内部客户端、verification_ref 复查、rt-v1 签票、服务账号分型的真实链路测试。
 * 全部走真实 PG iam_test + 真实 Redis DB1，无 mock 授权。
 */
@SpringBootTest
@ActiveProfiles("it")
class InternalClientIntegrationTest {

    private static final String PASSWORD = "Test123!Pass";
    private static final String RT_CLIENT = "it-runtime-client";
    private static final String RT_SECRET = "rt-secret-0123456789abcdef0123456789ab";
    private static final String READ_CLIENT = "it-read-client";
    private static final String READ_SECRET = "read-secret-0123456789abcdef0123456789";
    private static final String NOSCOPE_CLIENT = "it-noscope-client";
    private static final String NOSCOPE_SECRET = "noscope-secret-0123456789abcdef01234567";
    private static final String KNOWLEDGE_CLIENT = "it-knowledge-client";
    private static final String KNOWLEDGE_SECRET = "knowledge-secret-0123456789abcdef0123456";
    static final String RUNTIME_AUD = "langgraph-runtime";
    private static final String KNOWLEDGE_AUD = "knowledge";

    private static final UUID U_PLATFORM = UUID.fromString("01931000-0000-4000-8000-000000000001");
    private static final UUID U_ADMIN_A = UUID.fromString("01931000-0000-4000-8000-000000000002");
    private static final UUID U_MEMBER_A = UUID.fromString("01931000-0000-4000-8000-000000000003");
    private static final UUID ROLE_PLATFORM_SUPER_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000301");
    private static final UUID ROLE_TENANT_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000311");
    private static final UUID ROLE_TENANT_READER = UUID.fromString(
            "01930000-0000-4000-8000-000000000312");
    private static final UUID T_A = UUID.fromString("01931000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01931000-0000-4100-8100-000000001002");
    private static final UUID M_ADMIN_A = UUID.fromString("01931000-0000-4300-8300-000000003001");
    private static final UUID M_MEMBER_A = UUID.fromString("01931000-0000-4300-8300-000000003002");
    private static final UUID M_ADMIN_A_IN_B = UUID.fromString("01931000-0000-4300-8300-000000003006");
    private static final UUID PERM_KNOWLEDGE_READ = UUID.fromString(
            "01930000-0000-4000-8000-000000000201");

    @Autowired
    private SessionService sessionService;
    @Autowired
    private IntrospectionService introspectionService;
    @Autowired
    private RuntimeTicketService runtimeTicketService;
    @Autowired
    private ServiceAccountService serviceAccountService;
    @Autowired
    private InternalClientAuthenticator authenticator;
    @Autowired
    private InternalClientInterceptor interceptor;
    @Autowired
    private PasswordHasher passwordHasher;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private IamProperties props;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private org.springframework.data.redis.core.StringRedisTemplate redis;

    @Value("${spring.flyway.url}")
    private String migrateJdbcUrl;
    @Value("${spring.flyway.user}")
    private String migrateUser;
    @Value("${spring.flyway.password}")
    private String migratePassword;

    private InternalClient rt;
    private InternalClient read;
    private InternalClient knowledge;

    @BeforeEach
    void resetAndSeed() throws Exception {
        String hash = passwordHasher.hash(PASSWORD);
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            try (Statement st = con.createStatement()) {
                st.execute("TRUNCATE iam.internal_clients, iam.verification_refs, iam.service_tokens, "
                        + "iam.service_accounts, iam.tenants, iam.users, iam.auth_sessions, iam.audit_logs, "
                        + "iam.outbox, iam.sso_clients, iam.browser_handles, iam.bootstrap_meta CASCADE");
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
                seedUsers(con, hash);
                seedTenantsAndMembers(con);
                seedInternalClient(con, RT_CLIENT, OpaqueTokens.digest(RT_SECRET),
                        new String[]{"identity:introspect", "runtime-ticket:issue"},
                        new String[]{RUNTIME_AUD});
                seedInternalClient(con, READ_CLIENT, OpaqueTokens.digest(READ_SECRET),
                        new String[]{"identity:introspect"},
                        new String[]{"air-agent"});
                seedInternalClient(con, NOSCOPE_CLIENT, OpaqueTokens.digest(NOSCOPE_SECRET),
                        new String[]{}, new String[]{RUNTIME_AUD});
                seedInternalClient(con, KNOWLEDGE_CLIENT, OpaqueTokens.digest(KNOWLEDGE_SECRET),
                        new String[]{"identity:introspect"}, new String[]{KNOWLEDGE_AUD});
                con.commit();
            } finally {
                con.close();
            }
        }
        rt = new InternalClient(RT_CLIENT, "rt",
                List.of("identity:introspect", "runtime-ticket:issue"), List.of(RUNTIME_AUD), "active");
        read = new InternalClient(READ_CLIENT, "read",
                List.of("identity:introspect"), List.of("air-agent"), "active");
        knowledge = new InternalClient(KNOWLEDGE_CLIENT, "knowledge",
                List.of("identity:introspect"), List.of(KNOWLEDGE_AUD), "active");
    }

    // ================================================================ C12

    @Test
    void c12_authenticatorRejectsUnknownClientBadSecretAndMalformedBasic() {
        ApiException unknown = assertThrows(ApiException.class, () ->
                authenticator.authenticate(basic("ghost-client", RT_SECRET)));
        assertEquals(401, unknown.status());
        ApiException badSecret = assertThrows(ApiException.class, () ->
                authenticator.authenticate(basic(RT_CLIENT, "wrong-secret")));
        assertEquals(401, badSecret.status());
        assertThrows(ApiException.class, () -> authenticator.authenticate("Bearer abc"));
        assertThrows(ApiException.class, () -> authenticator.authenticate("Basic ####"));

        InternalClient ok = authenticator.authenticate(basic(RT_CLIENT, RT_SECRET));
        assertEquals(RT_CLIENT, ok.clientId());
        assertTrue(ok.hasScope("runtime-ticket:issue"));
    }

    @Test
    void c12_interceptorRejectsMissingScope() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST",
                "/v1/internal/identity/introspect");
        request.addHeader("Authorization", basic(NOSCOPE_CLIENT, NOSCOPE_SECRET));
        ApiException ex = assertThrows(ApiException.class, () ->
                interceptor.preHandle(request, new MockHttpServletResponse(), new Object()));
        assertEquals(403, ex.status());
    }

    @Test
    void c12_garbageSubjectReturnsInactive200NotError() {
        Object result = introspectionService.introspect(rt,
                new IntrospectDTO("totally-not-a-token", null, RUNTIME_AUD, null, null));
        assertInactive(result, "invalid_or_revoked");
    }

    @Test
    void c12_clientAudienceWhitelistEnforced() {
        String token = loginAndSwitch("adminA", T_A);
        ApiException ex = assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO(token, null, "air-agent", null, null)));
        assertEquals(403, ex.status());
    }

    @Test
    void c12_subjectAndExecutionContextMutuallyExclusive() {
        assertEquals(400, assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO(null, null, RUNTIME_AUD, null, null))).status());
        assertEquals(400, assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO("tok", new ExecutionContextRefDTO("ref", null),
                        RUNTIME_AUD, null, null))).status());
        assertEquals(400, assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO(null, null, " ", null, null))).status());
    }

    @Test
    void c12_activeHumanIntrospectionReturnsTypedIdentity() {
        String token = loginAndSwitch("adminA", T_A);
        Object result = introspectionService.introspect(rt,
                new IntrospectDTO(token, null, RUNTIME_AUD,
                        new ExpectedContextDTO(T_A.toString(), 2L), null));
        IdentityVO identity = (IdentityVO) result;
        assertTrue(identity.active());
        assertEquals(RUNTIME_AUD, identity.audience());
        assertFalse(identity.platformAdmin());
        assertTrue(identity.platformRoles().isEmpty());
        assertTrue(identity.permissions().stream().noneMatch(code -> code.startsWith("platform:")));
        assertEquals("human", identity.principal().type());
        assertEquals("workforce", identity.principal().realm());
        assertEquals(T_A.toString(), identity.currentTenant().id());
        assertEquals(2L, identity.contextVersion());
        assertTrue(identity.permissions().contains("tenant:member:read"),
                "内部核验应返回企业有效权限全集");
        assertNotNull(identity.session().id());

        // expected_context 过期：失败关闭 409，不回新身份
        ApiException stale = assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO(token, null, RUNTIME_AUD,
                        new ExpectedContextDTO(T_B.toString(), 2L), null)));
        assertEquals(409, stale.status());
    }

    @Test
    void c12_suspendedTenantHumanTokenIntrospectsInactive() {
        String token = loginAndSwitch("adminA", T_A);
        migrateTx("UPDATE iam.tenants SET status = 'suspended' WHERE id = '" + T_A + "'");
        Object result = introspectionService.introspect(rt,
                new IntrospectDTO(token, null, RUNTIME_AUD, null, null));
        assertInactive(result, "tenant_suspended");
    }

    // ================================================================ C13

    @Test
    void missingRedisSessionRejectsBothTokenAndExecutionReference() {
        String token = loginAndSwitch("adminA", T_A);
        JsonNode context = issueExecutionContext(token);
        redis.delete("Authorization:login:token:" + OpaqueTokens.digest(token));
        assertInactive(introspectionService.introspect(rt,
                new IntrospectDTO(token, null, RUNTIME_AUD, null, false)), "invalid_or_revoked");
        assertRecheckInactive(introspectionService.introspect(rt, new IntrospectDTO(null,
                new ExecutionContextRefDTO(context.path("verification_ref").asText(),
                        parseRevisions(context.path("revisions"))), RUNTIME_AUD, null, false)), "invalid_or_revoked");
    }

    @Test
    void c13_refIssuedThenRechecksActiveWithLiveRevisions() {
        String token = loginAndSwitch("adminA", T_A);
        JsonNode ec = issueExecutionContext(token);
        RevisionsDTO stored = parseRevisions(ec.path("revisions"));

        Object recheck = introspectionService.introspect(rt,
                new IntrospectDTO(null,
                        new ExecutionContextRefDTO(ec.path("verification_ref").asText(), stored),
                        RUNTIME_AUD, null, null));
        RecheckActiveVO active = (RecheckActiveVO) recheck;
        assertTrue(active.active());
        assertTrue(active.contextMatches());
        assertEquals(stored, active.revisions());
    }

    @Test
    void c13_forgedOrForeignRefRejected() {
        Object forged = introspectionService.introspect(rt,
                new IntrospectDTO(null,
                        new ExecutionContextRefDTO(UUID.randomUUID().toString(), zeroRevisions()),
                        RUNTIME_AUD, null, null));
        assertRecheckInactive(forged, "invalid_or_revoked");

        // 绑定其他客户端：同 ref 换客户端身份查询必须查不到
        String token = loginAndSwitch("adminA", T_A);
        JsonNode ec = issueExecutionContext(token);
        InternalClient impostor = new InternalClient("other-rt", "x",
                List.of("identity:introspect", "runtime-ticket:issue"), List.of(RUNTIME_AUD), "active");
        Object foreign = introspectionService.introspect(impostor,
                new IntrospectDTO(null,
                        new ExecutionContextRefDTO(ec.path("verification_ref").asText(), zeroRevisions()),
                        RUNTIME_AUD, null, null));
        assertRecheckInactive(foreign, "invalid_or_revoked");
    }

    @Test
    void c13_revisionChangeAfterIssuanceRejectsRecheck() {
        String token = loginAndSwitch("adminA", T_A); // ctx=2
        JsonNode ec = issueExecutionContext(token);
        RevisionsDTO stored = parseRevisions(ec.path("revisions"));
        assertEquals(2L, stored.sessionCtxVersion());

        // A→B：ctx 推进到 3，原引用修订立即失配（A→B→A 迟到响应当被丢弃的服务端基础）
        sessionService.switchTenant(token, new SwitchTenantDTO(T_B.toString(), 2L));
        Object changed = introspectionService.introspect(rt,
                new IntrospectDTO(null,
                        new ExecutionContextRefDTO(ec.path("verification_ref").asText(), stored),
                        RUNTIME_AUD, null, null));
        assertRecheckInactive(changed, "revision_mismatch");
    }

    @Test
    void c13_sessionRevokedRejectsRecheck() {
        String token = loginAndSwitch("memberA", T_A);
        JsonNode ec = issueExecutionContext(token);
        RevisionsDTO stored = parseRevisions(ec.path("revisions"));
        sessionService.logout(token);
        Object recheck = introspectionService.introspect(rt,
                new IntrospectDTO(null,
                        new ExecutionContextRefDTO(ec.path("verification_ref").asText(), stored),
                        RUNTIME_AUD, null, null));
        assertRecheckInactive(recheck, "invalid_or_revoked");
    }

    @Test
    void c13_refValidityBoundedByHoursIndependentOf60sTicket() throws Exception {
        String token = loginAndSwitch("adminA", T_A);
        JsonNode ec = issueExecutionContext(token);
        OffsetDateTime validUntil = OffsetDateTime.parse(ec.path("valid_until").asText());
        long ttlSeconds = props.internal().verificationRefTtlSeconds();
        // 引用 TTL 以小时计（默认 12h），与 60s 短入口票据互不影响
        assertTrue(validUntil.toEpochSecond() - Instant.now().getEpochSecond() >= ttlSeconds - 300,
                "verification_ref 上界应接近配置 TTL");
        assertTrue(Duration.ofSeconds(ttlSeconds).toMinutes() >= 60);
    }

    @Test
    void c13_includeExecutionContextRuntimeOnly() {
        String token = login("memberA");
        ApiException ex = assertThrows(ApiException.class, () -> introspectionService.introspect(read,
                new IntrospectDTO(token, null, "air-agent", null, true)));
        assertEquals(400, ex.status());
    }

    @Test
    void c13_noSecretMaterialInVerificationRefRow() throws Exception {
        String token = loginAndSwitch("adminA", T_A);
        issueExecutionContext(token);
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement();
             var rs = st.executeQuery("SELECT to_jsonb(r)::text FROM iam.verification_refs r")) {
            assertTrue(rs.next());
            String row = rs.getString(1);
            assertFalse(row.contains(token), "引用行不得包含原始 subject token");
            assertFalse(row.contains(OpaqueTokens.digest(token)), "引用行不得包含令牌摘要");
        }
    }

    // ================================================================ C03

    @Test
    void c03_runtimeTicketSignedAndVerifiableWithLiveRevisions() {
        String token = loginAndSwitch("adminA", T_A); // ctx=2
        RuntimeTicketVO ticket = runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(token, RUNTIME_AUD, T_A.toString(), 2L));
        assertEquals("Bearer", ticket.tokenType());
        assertEquals("rt-v1", ticket.format());
        assertEquals(RUNTIME_AUD, ticket.audience());
        assertEquals(60L, ticket.expiresIn());

        RtV1VerifyResult result = RtV1Codec.verify(ticket.ticket(), props.rt().kid(),
                props.rt().secret().getBytes(StandardCharsets.UTF_8),
                RUNTIME_AUD, Instant.now().getEpochSecond());
        assertTrue(result.ok(), "票据验签应成功: " + result.reason());
        assertEquals(T_A, result.body().tid());
        assertEquals(U_ADMIN_A, result.body().uid());
        assertEquals(M_ADMIN_A, result.body().mid());
        assertEquals(2L, result.body().crev());
        assertTrue(result.body().exp() - result.body().iat() <= 60);
    }

    @Test
    void c03_ticketCtxMismatch409AndNoTenant403() {
        String token = loginAndSwitch("adminA", T_A);
        ApiException wrongTenant = assertThrows(ApiException.class, () -> runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(token, RUNTIME_AUD, T_B.toString(), 2L)));
        assertEquals(409, wrongTenant.status());
        ApiException staleCtx = assertThrows(ApiException.class, () -> runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(token, RUNTIME_AUD, T_A.toString(), 1L)));
        assertEquals(409, staleCtx.status());

        String noTenant = login("memberA");
        ApiException noCtx = assertThrows(ApiException.class, () -> runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(noTenant, RUNTIME_AUD, T_A.toString(), 1L)));
        assertEquals(403, noCtx.status());
    }

    @Test
    void c03_ticketRejectsTamperWrongAudienceKidAndExpiry() {
        String token = loginAndSwitch("adminA", T_A);
        RuntimeTicketVO ticket = runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(token, RUNTIME_AUD, T_A.toString(), 2L));

        char last = ticket.ticket().charAt(ticket.ticket().length() - 1);
        String tampered = ticket.ticket().substring(0, ticket.ticket().length() - 1)
                + (last == 'A' ? 'B' : 'A');
        assertFalse(RtV1Codec.verify(tampered, props.rt().kid(),
                props.rt().secret().getBytes(StandardCharsets.UTF_8),
                RUNTIME_AUD, Instant.now().getEpochSecond()).ok());
        assertFalse(RtV1Codec.verify(ticket.ticket(), props.rt().kid(),
                props.rt().secret().getBytes(StandardCharsets.UTF_8),
                "knowledge", Instant.now().getEpochSecond()).ok());
        assertFalse(RtV1Codec.verify(ticket.ticket(), "wrong-kid",
                props.rt().secret().getBytes(StandardCharsets.UTF_8),
                RUNTIME_AUD, Instant.now().getEpochSecond()).ok());
        assertFalse(RtV1Codec.verify(ticket.ticket(), props.rt().kid(),
                props.rt().secret().getBytes(StandardCharsets.UTF_8),
                RUNTIME_AUD, Instant.now().getEpochSecond() + 120).ok());
    }

    // ================================================================ C15

    @Test
    void c15_serviceAccountTokenLifecycleAndMachineIdentityShape() {
        CurrentSession platform = platformSession();
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-knowledge-test", "知识库测试服务账号",
                        T_A.toString(), List.of("knowledge"), 90,
                        List.of("tenant:member:read")));
        ServiceTokenIssuedVO issued = serviceAccountService.issueToken(platform, sa.id(),
                new CreateServiceTokenDTO(null));
        assertEquals(43, issued.secret().length(), "一次性秘密为 random-128 不透明令牌");
        assertEquals(1L, issued.credentialRevision());
        assertNotNull(issued.credentialId());

        Object introspected = introspectionService.introspect(knowledge,
                new IntrospectDTO(issued.secret(), null, KNOWLEDGE_AUD, null, null));
        ServiceIdentityVO identity = (ServiceIdentityVO) introspected;
        assertTrue(identity.active());
        assertEquals("service_account", identity.principal().type());
        assertEquals("service", identity.principal().realm());
        assertNull(identity.user());
        assertNull(identity.session());
        assertNull(identity.membership());
        assertEquals(T_A.toString(), identity.currentTenant().id());
        assertEquals(List.of("tenant:member:read"), identity.permissions());
        assertEquals(1L, identity.credentialRevision());
        assertEquals(issued.credentialId(), identity.credentialId());
        assertNull(identity.revisions(), "四修订对机器主体整体不适用（契约：null）");

        serviceAccountService.revokeToken(platform, issued.credentialId());
        Object afterRevoke = introspectionService.introspect(knowledge,
                new IntrospectDTO(issued.secret(), null, KNOWLEDGE_AUD, null, null));
        assertInactive(afterRevoke, "invalid_or_revoked");
    }

    @Test
    void c15_credentialRotationOverlapAndExpiryGuards() {
        CurrentSession platform = platformSession();
        ServiceAccountVO shortSa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-thirty-days", "30天服务账号",
                        T_A.toString(), List.of("knowledge"), 30, List.of()));
        ServiceTokenIssuedVO first = serviceAccountService.issueToken(platform, shortSa.id(),
                new CreateServiceTokenDTO(null));
        // 默认令牌 90 天，但必须被服务账号 30 天上界截短
        OffsetDateTime tokenExpiry = OffsetDateTime.parse(first.expiresAt());
        assertTrue(Duration.between(OffsetDateTime.now(), tokenExpiry).toDays() <= 31);

        migrateTx("UPDATE iam.service_tokens SET issued_at = clock_timestamp() - interval '2 days' "
                + "WHERE credential_id = '" + first.credentialId() + "'");
        ServiceTokenIssuedVO second = serviceAccountService.issueToken(platform, shortSa.id(),
                new CreateServiceTokenDTO(24));
        assertEquals(2L, second.credentialRevision());
        assertNotNull(second.overlapUntil());
        // 双令牌重叠窗口内，旧凭据仍可用
        Object oldStillActive = introspectionService.introspect(knowledge,
                new IntrospectDTO(first.secret(), null, KNOWLEDGE_AUD, null, null));
        assertTrue(((ServiceIdentityVO) oldStillActive).active());

        migrateTx("UPDATE iam.service_tokens SET overlap_until = clock_timestamp() - interval '1 second' "
                + "WHERE credential_id = '" + first.credentialId() + "'");
        assertInactive(introspectionService.introspect(knowledge,
                new IntrospectDTO(first.secret(), null, KNOWLEDGE_AUD, null, null)), "invalid_or_revoked");
        ServiceTokenIssuedVO third = serviceAccountService.issueToken(platform, shortSa.id(),
                new CreateServiceTokenDTO(0));
        assertInactive(introspectionService.introspect(knowledge,
                new IntrospectDTO(second.secret(), null, KNOWLEDGE_AUD, null, null)), "invalid_or_revoked");
        assertTrue(((ServiceIdentityVO) introspectionService.introspect(knowledge,
                new IntrospectDTO(third.secret(), null, KNOWLEDGE_AUD, null, null))).active());

        assertEquals(400, assertThrows(ApiException.class, () -> serviceAccountService.issueToken(
                platform, shortSa.id(), new CreateServiceTokenDTO(25))).status());
        assertEquals(400, assertThrows(ApiException.class, () -> serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-too-long", "超期",
                        T_A.toString(), List.of("knowledge"), 366, List.of()))).status());
    }

    @Test
    void c15_disabledAccountAndSuspendedTenantRejectMachineIdentity() {
        CurrentSession platform = platformSession();
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-disable-test", "停用测试",
                        T_A.toString(), List.of("knowledge"), 90, List.of("tenant:member:read")));
        ServiceTokenIssuedVO issued = serviceAccountService.issueToken(platform, sa.id(),
                new CreateServiceTokenDTO(null));

        migrateTx("UPDATE iam.service_accounts SET status = 'disabled' WHERE id = '" + sa.id() + "'");
        assertInactive(introspectionService.introspect(knowledge,
                new IntrospectDTO(issued.secret(), null, KNOWLEDGE_AUD, null, null)),
                "account_disabled");

        migrateTx("UPDATE iam.service_accounts SET status = 'active' WHERE id = '" + sa.id() + "'");
        migrateTx("UPDATE iam.tenants SET status = 'suspended' WHERE id = '" + T_A + "'");
        assertInactive(introspectionService.introspect(knowledge,
                new IntrospectDTO(issued.secret(), null, KNOWLEDGE_AUD, null, null)),
                "tenant_suspended");
    }

    @Test
    void c15_resourcePermissionDefaultDeniedAtAppLayerAndDbTrigger() {
        CurrentSession platform = platformSession();
        // 应用层：资源型权限码不允许在 I1 授予服务账号
        ApiException denied = assertThrows(ApiException.class, () -> serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-resource-x", "资源越权",
                        T_A.toString(), List.of("knowledge"), 90,
                        List.of("knowledge:lib:air:read"))));
        assertEquals(400, denied.status());

        // 数据库层：绕过应用直插同样被触发器拒绝（纵深防御）
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-resource-guard", "触发器验证",
                        T_A.toString(), List.of("knowledge"), 90, List.of()));
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            con.setAutoCommit(false);
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                SQLException ex = assertThrows(SQLException.class, () -> st.execute(
                        "INSERT INTO iam.service_account_permissions("
                                + "tenant_id, service_account_id, permission_id, granted_by) VALUES ('"
                                + T_A + "','" + sa.id() + "','" + PERM_KNOWLEDGE_READ + "','"
                                + U_PLATFORM + "')"));
                assertEquals("23514", ex.getSQLState());
                con.rollback();
            } finally {
                con.close();
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void c15_serviceTokenCannotIssueRuntimeTicketAndIsAudienceBound() {
        CurrentSession platform = platformSession();
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-isolation", "分型隔离",
                        T_A.toString(), List.of("knowledge"), 90, List.of()));
        ServiceTokenIssuedVO issued = serviceAccountService.issueToken(platform, sa.id(),
                new CreateServiceTokenDTO(null));

        // 机器令牌不能换人类运行票（无会话/无成员）
        ApiException noTicket = assertThrows(ApiException.class, () -> runtimeTicketService.issue(rt,
                new RuntimeTicketDTO(issued.secret(), RUNTIME_AUD, T_A.toString(), 1L)));
        assertEquals(401, noTicket.status());

        // 受众绑定：knowledge 受众的服务令牌不得按 langgraph-runtime 核验
        ApiException aud = assertThrows(ApiException.class, () -> introspectionService.introspect(rt,
                new IntrospectDTO(issued.secret(), null, RUNTIME_AUD, null, null)));
        assertEquals(403, aud.status());
    }

    @Test
    void c15_auditAndDbNeverContainRawServiceSecret() throws Exception {
        CurrentSession platform = platformSession();
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-secret-scan", "秘密扫描",
                        T_A.toString(), List.of("knowledge"), 90, List.of()));
        ServiceTokenIssuedVO issued = serviceAccountService.issueToken(platform, sa.id(),
                new CreateServiceTokenDTO(2));
        serviceAccountService.revokeToken(platform, issued.credentialId());

        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement()) {
            try (var rs = st.executeQuery(
                    "SELECT count(*) FROM iam.audit_logs WHERE detail::text LIKE '%"
                            + issued.secret() + "%'")) {
                rs.next();
                assertEquals(0L, rs.getLong(1), "审计 detail 不得出现原始秘密");
            }
            try (var rs = st.executeQuery(
                    "SELECT count(*) FROM iam.service_tokens WHERE token_digest = '"
                            + issued.secret() + "'")) {
                rs.next();
                assertEquals(0L, rs.getLong(1), "库内不得存原始秘密");
            }
            try (var rs = st.executeQuery(
                    "SELECT count(*) FROM iam.service_tokens WHERE token_digest = '"
                            + OpaqueTokens.digest(issued.secret()) + "'")) {
                rs.next();
                assertEquals(1L, rs.getLong(1), "库内只存摘要");
            }
        }
    }

    // ================================================================ helpers

    private void seedUsers(Connection con, String hash) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
            ps.setObject(1, U_PLATFORM);
            ps.setString(2, "platformAdmin");
            ps.setString(3, "平台超管");
            ps.setString(4, hash);
            ps.executeUpdate();
            ps.setObject(1, U_ADMIN_A);
            ps.setString(2, "adminA");
            ps.setString(3, "企业A管理员");
            ps.setString(4, hash);
            ps.executeUpdate();
            ps.setObject(1, U_MEMBER_A);
            ps.setString(2, "memberA");
            ps.setString(3, "企业A只读");
            ps.setString(4, hash);
            ps.executeUpdate();
        }
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.user_roles(user_id, role_id, granted_by) VALUES (?,?,?)")) {
            ps.setObject(1, U_PLATFORM);
            ps.setObject(2, ROLE_PLATFORM_SUPER_ADMIN);
            ps.setObject(3, U_PLATFORM);
            ps.executeUpdate();
        }
    }

    private void seedTenantsAndMembers(Connection con) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.tenants(id, code, name, created_by) VALUES (?,?,?,?),(?,?,?,?)")) {
            ps.setObject(1, T_A);
            ps.setString(2, "TENANT-A");
            ps.setString(3, "测试企业A");
            ps.setObject(4, U_ADMIN_A);
            ps.setObject(5, T_B);
            ps.setString(6, "TENANT-B");
            ps.setString(7, "测试企业B");
            ps.setObject(8, U_ADMIN_A);
            ps.executeUpdate();
        }
        insertMembership(con, M_ADMIN_A, T_A, U_ADMIN_A);
        insertMembership(con, M_MEMBER_A, T_A, U_MEMBER_A);
        insertMembership(con, M_ADMIN_A_IN_B, T_B, U_ADMIN_A);
        insertMembershipRole(con, T_A, M_ADMIN_A, ROLE_TENANT_ADMIN);
        insertMembershipRole(con, T_A, M_MEMBER_A, ROLE_TENANT_READER);
        insertMembershipRole(con, T_B, M_ADMIN_A_IN_B, ROLE_TENANT_READER);
    }

    private void insertMembership(Connection con, UUID id, UUID tenant, UUID user) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.tenant_memberships(id, tenant_id, user_id) VALUES (?,?,?)")) {
            ps.setObject(1, id);
            ps.setObject(2, tenant);
            ps.setObject(3, user);
            ps.executeUpdate();
        }
    }

    private void insertMembershipRole(Connection con, UUID tenant, UUID membership, UUID role)
            throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by) "
                        + "VALUES (?,?,?,?)")) {
            ps.setObject(1, tenant);
            ps.setObject(2, membership);
            ps.setObject(3, role);
            ps.setObject(4, U_ADMIN_A);
            ps.executeUpdate();
        }
    }

    private void seedInternalClient(Connection con, String clientId, String digest,
                                    String[] scopes, String[] audiences) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences) "
                        + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, clientId);
            ps.setString(2, clientId);
            ps.setString(3, digest);
            ps.setObject(4, con.createArrayOf("text", scopes));
            ps.setObject(5, con.createArrayOf("text", audiences));
            ps.executeUpdate();
        }
    }

    private String login(String account) {
        LoginVO result = sessionService.login(
                new LoginDTO(account, PASSWORD, "workforce", "iam-admin"));
        return result.accessToken();
    }

    private String loginAndSwitch(String account, UUID tenant) {
        String token = login(account);
        sessionService.switchTenant(token, new SwitchTenantDTO(tenant.toString(), 1L));
        return token;
    }

    private CurrentSession platformSession() {
        return sessionService.requireCurrent(login("platformAdmin"));
    }

    private String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private JsonNode issueExecutionContext(String humanToken) {
        Object result = introspectionService.introspect(rt,
                new IntrospectDTO(humanToken, null, RUNTIME_AUD, null, true));
        JsonNode node = mapper.convertValue(result, JsonNode.class);
        assertTrue(node.path("execution_context").isObject());
        return node.path("execution_context");
    }

    private RevisionsDTO parseRevisions(JsonNode node) {
        return new RevisionsDTO(
                node.path("user_auth_revision").asLong(),
                node.path("tenant_auth_revision").asLong(),
                node.path("membership_revision").asLong(),
                node.path("session_ctx_version").asLong());
    }

    private RevisionsDTO zeroRevisions() {
        return new RevisionsDTO(0L, 0L, 0L, 0L);
    }

    private void assertInactive(Object result, String reason) {
        InactiveIntrospectionVO inactive = (InactiveIntrospectionVO) result;
        assertFalse(inactive.active());
        assertEquals("iam.introspection.v1", inactive.schemaVersion());
        assertEquals(reason, inactive.reason());
        assertNotNull(inactive.evaluatedAt());
    }

    private void assertRecheckInactive(Object result, String reason) {
        RecheckInactiveVO inactive = (RecheckInactiveVO) result;
        assertFalse(inactive.active());
        assertFalse(inactive.contextMatches());
        assertEquals(reason, inactive.reason());
    }

    private void migrateTx(String sql) {
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            con.setAutoCommit(false);
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                int affected = st.executeUpdate(sql);
                assertTrue(affected > 0, "管理侧 DML 应命中行：" + sql);
                con.commit();
            } catch (SQLException e) {
                con.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
