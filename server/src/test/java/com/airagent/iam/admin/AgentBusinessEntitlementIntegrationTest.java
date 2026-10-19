package com.airagent.iam.admin;

import com.airagent.iam.security.password.PasswordHasher;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.StreamUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Agent 业务授权端到端回归：目录登记、企业开通与角色求交、资源/权限停用修订、
 * 平台/模板写边界，以及 me 与 Bearer 内省的一致性。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
class AgentBusinessEntitlementIntegrationTest {

    private static final String PASSWORD = "Business-It-Only-123!";
    private static final String CLIENT_ID = "it-business-client";
    private static final String CLIENT_SECRET = "business-secret-0123456789abcdef012345";
    private static final String BASIC_QA = "agent:business:basic-qa";
    private static final String BASIC_QA_USE = BASIC_QA + ":use";
    private static final String ANALYSIS = "agent:business:data-analysis";
    private static final String ANALYSIS_USE = ANALYSIS + ":use";
    private static final UUID ROLE_PLATFORM_SUPER_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000301");
    private static final UUID ROLE_TENANT_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000311");
    private static final UUID U_ROOT = UUID.fromString("01932000-0000-4000-8000-000000000001");
    private static final UUID U_ADMIN = UUID.fromString("01932000-0000-4000-8000-000000000002");
    private static final UUID U_MEMBER = UUID.fromString("01932000-0000-4000-8000-000000000003");
    private static final UUID T_A = UUID.fromString("01932000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01932000-0000-4100-8100-000000001002");
    private static final UUID M_ADMIN_A = UUID.fromString("01932000-0000-4300-8300-000000003001");
    private static final UUID M_ADMIN_B = UUID.fromString("01932000-0000-4300-8300-000000003002");
    private static final UUID M_MEMBER_A = UUID.fromString("01932000-0000-4300-8300-000000003003");
    private static final UUID M_MEMBER_B = UUID.fromString("01932000-0000-4300-8300-000000003004");

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PasswordHasher hasher;
    @Value("${spring.flyway.url}") String ownerUrl;
    @Value("${spring.flyway.user}") String ownerUser;
    @Value("${spring.flyway.password}") String ownerPassword;
    @Value("${spring.datasource.url}") String appUrl;
    @Value("${spring.datasource.username}") String appUser;
    @Value("${spring.datasource.password}") String appPassword;

    private String rootToken;
    private JsonNode rootIdentity;

    @BeforeEach
    void seedOwnedTestDatabase() throws Exception {
        String hash = hasher.hash(PASSWORD);
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("TRUNCATE iam.resource_catalog, iam.tenants, iam.users, iam.auth_sessions, "
                    + "iam.audit_logs, iam.outbox, iam.internal_clients, iam.sso_clients, "
                    + "iam.browser_handles, iam.bootstrap_meta, iam.verification_refs, "
                    + "iam.service_tokens, iam.service_accounts CASCADE");
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.execute("INSERT INTO iam.resource_catalog(code,name_zh,sort,status,kind,parent_code) "
                    + "VALUES ('knowledge:lib:air','空气知识库',10,'active','leaf','knowledge') ON CONFLICT (code) DO NOTHING");
            st.execute(migration("V2__seed_catalog.sql"));
            st.execute("INSERT INTO iam.permissions(id,code,name_zh,scope,grantable_to_tenants,sort) "
                    + "VALUES ('01930000-0000-4000-8000-000000000211','tenant:resource:grant','企业资源授权管理','tenant',true,211) ON CONFLICT DO NOTHING");
            st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT r.id,p.id "
                    + "FROM iam.roles r JOIN iam.permissions p ON p.code='tenant:resource:grant' "
                    + "WHERE r.code='tenant_admin' AND r.tenant_id IS NULL ON CONFLICT DO NOTHING");
            st.execute(migration("V24__agent_business_entitlements.sql"));

            insertUser(con, U_ROOT, "root", "Agent 测试 root", hash);
            insertUser(con, U_ADMIN, "bizAdmin", "业务管理员", hash);
            insertUser(con, U_MEMBER, "bizMember", "业务成员", hash);
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.user_roles(user_id, role_id, granted_by) VALUES (?,?,?)")) {
                ps.setObject(1, U_ROOT);
                ps.setObject(2, ROLE_PLATFORM_SUPER_ADMIN);
                ps.setObject(3, U_ROOT);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.tenants(id, code, name, created_by) VALUES (?,?,?,?),(?,?,?,?)")) {
                ps.setObject(1, T_A); ps.setString(2, "BIZ-A"); ps.setString(3, "业务甲企业"); ps.setObject(4, U_ADMIN);
                ps.setObject(5, T_B); ps.setString(6, "BIZ-B"); ps.setString(7, "业务乙企业"); ps.setObject(8, U_ADMIN);
                ps.executeUpdate();
            }
            insertMembership(con, M_ADMIN_A, T_A, U_ADMIN);
            insertMembership(con, M_ADMIN_B, T_B, U_ADMIN);
            insertMembership(con, M_MEMBER_A, T_A, U_MEMBER);
            insertMembership(con, M_MEMBER_B, T_B, U_MEMBER);
            insertMembershipRole(con, T_A, M_ADMIN_A, ROLE_TENANT_ADMIN);
            insertMembershipRole(con, T_B, M_ADMIN_B, ROLE_TENANT_ADMIN);
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.internal_clients(client_id,name,secret_digest,scopes,audiences) "
                            + "VALUES (?,?,?,?,?)")) {
                ps.setString(1, CLIENT_ID);
                ps.setString(2, "业务内省客户端");
                ps.setString(3, com.airagent.iam.security.token.OpaqueTokens.digest(CLIENT_SECRET));
                ps.setObject(4, con.createArrayOf("text", new String[]{"identity:introspect"}));
                ps.setObject(5, con.createArrayOf("text", new String[]{"air-agent", "langgraph-runtime"}));
                ps.executeUpdate();
            }
            con.commit();
        }
        JsonNode login = login("root");
        rootToken = login.path("access_token").asText();
        rootIdentity = login.path("identity");
    }

    @Test
    void catalogRegistersThreeBusinessesWithChineseNamesAndNoAutoGrant() throws Exception {
        JsonNode page = call("GET", "/v1/admin/resources?limit=200", null, rootToken, 200);
        List<String> codes = new ArrayList<>();
        for (JsonNode item : page.path("items")) {
            codes.add(item.path("code").asText());
            if (item.path("code").asText().startsWith("agent:business:")) {
                assertTrue(List.of("基础问答", "数据分析", "智能溯源").contains(item.path("name_zh").asText()));
                assertEquals("active", item.path("status").asText());
                assertEquals(1, item.path("permissions").size());
                assertTrue(item.path("permissions").get(0).path("code").asText()
                        .equals(item.path("code").asText() + ":use"));
            }
        }
        assertTrue(codes.containsAll(List.of(BASIC_QA, ANALYSIS, "agent:business:intelligent-tracing")));

        String member = login("bizMember").path("access_token").asText();
        JsonNode identity = switchTenant(member, T_A, 1);
        assertFalse(identity.path("permissions").toString().contains("agent:business:"));
    }

    @Test
    void entitlementAndTenantRoleIntersectionWithCrossTenantIsolation() throws Exception {
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        call("POST", "/v1/admin/roles", roleBody("biz_a", List.of(BASIC_QA_USE), identity),
                admin, 409); // 未开通

        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        admin = login("bizAdmin").path("access_token").asText();
        identity = switchTenant(admin, T_A, 1);
        JsonNode role = call("POST", "/v1/admin/roles",
                roleBody("biz_a", List.of(BASIC_QA_USE), identity), admin, 201);
        assignRole(admin, identity, M_MEMBER_A, List.of("biz_a"));

        String member = login("bizMember").path("access_token").asText();
        JsonNode memberA = switchTenant(member, T_A, 1);
        assertTrue(memberA.path("permissions").toString().contains(BASIC_QA_USE));

        JsonNode memberB = switchTenant(member, T_B, memberA.path("session").path("ctx_version").asLong());
        assertFalse(memberB.path("permissions").toString().contains(BASIC_QA_USE));

        // B 未开通，不能把 A 的业务码塞进 B 角色
        String adminB = login("bizAdmin").path("access_token").asText();
        JsonNode idB = switchTenant(adminB, T_B, 1);
        call("POST", "/v1/admin/roles", roleBody("biz_b", List.of(BASIC_QA_USE), idB), adminB, 409);

        // 平台角色不可携带业务码
        call("POST", "/v1/admin/roles", Map.of(
                "scope", "platform", "code", "platform_biz_bad", "name", "非法平台角色",
                "permission_codes", List.of(BASIC_QA_USE),
                "expected_context", context(rootIdentity), "expected_tenant_revision", 0),
                rootToken, 409);
        // 未知码整体拒绝（需保持在 A 企业上下文）
        String adminFresh = login("bizAdmin").path("access_token").asText();
        JsonNode idFresh = switchTenant(adminFresh, T_A, 1);
        call("POST", "/v1/admin/roles",
                roleBody("biz_unknown", List.of("agent:business:ghost:use"), idFresh), adminFresh, 400);
        assertNotNull(role.path("id").asText());
    }

    @Test
    void entitlementRevokeResourceDisableAndPermissionDisableEachInvalidateSessions() throws Exception {
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        call("POST", "/v1/admin/roles", roleBody("biz_a", List.of(BASIC_QA_USE), identity), admin, 201);
        assignRole(admin, identity, M_MEMBER_A, List.of("biz_a"));
        String member = login("bizMember").path("access_token").asText();
        JsonNode memberA = switchTenant(member, T_A, 1);
        assertTrue(memberA.path("permissions").toString().contains(BASIC_QA_USE));

        // 回收开通：旧会话立即失效，重新登录后业务码消失
        JsonNode ent = entitlementRow(T_A, BASIC_QA);
        call("PUT", "/v1/admin/tenants/" + T_A + "/entitlements/" + BASIC_QA, Map.of(
                "expected_context", context(rootIdentity),
                "expected_revision", ent.path("revision").asLong(),
                "expected_tenant_revision", ent.path("tenant_auth_revision").asLong(),
                "status", "revoked"), rootToken, 200);
        call("GET", "/v1/auth/me", null, member, 401);
        String member2 = login("bizMember").path("access_token").asText();
        JsonNode afterRevoke = switchTenant(member2, T_A, 1);
        assertFalse(afterRevoke.path("permissions").toString().contains(BASIC_QA_USE));

        // 恢复开通：原角色配置仍在，业务码恢复
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, ent.path("revision").asLong() + 1);
        String member3 = login("bizMember").path("access_token").asText();
        JsonNode restored = switchTenant(member3, T_A, 1);
        assertTrue(restored.path("permissions").toString().contains(BASIC_QA_USE));

        // 目录停用：企业修订推进，旧会话失效，新身份无业务码
        JsonNode resource = findResource(BASIC_QA);
        call("PATCH", "/v1/admin/resources/" + BASIC_QA, Map.of(
                "expected_context", context(rootIdentity),
                "expected_revision", resource.path("revision").asLong(),
                "status", "disabled"), rootToken, 200);
        call("GET", "/v1/auth/me", null, member3, 401);
        String member4 = login("bizMember").path("access_token").asText();
        assertFalse(switchTenant(member4, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));
        resource = findResource(BASIC_QA);
        call("PATCH", "/v1/admin/resources/" + BASIC_QA, Map.of(
                "expected_context", context(rootIdentity),
                "expected_revision", resource.path("revision").asLong(),
                "status", "active"), rootToken, 200);

        // 权限定义停用：V24 触发器推进成员/企业修订，重新登录后业务码消失
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.permissions SET status='disabled' WHERE code='" + BASIC_QA_USE + "'");
            con.commit();
        }
        String member5 = login("bizMember").path("access_token").asText();
        JsonNode beforeFresh = switchTenant(member5, T_A, 1);
        assertFalse(beforeFresh.path("permissions").toString().contains(BASIC_QA_USE));
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.permissions SET status='active' WHERE code='" + BASIC_QA_USE + "'");
            con.commit();
        }
        String member6 = login("bizMember").path("access_token").asText();
        assertTrue(switchTenant(member6, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));
    }

    @Test
    void bearerIntrospectionMatchesMeAndRecheckFailsAfterRoleRevocation() throws Exception {
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        JsonNode role = call("POST", "/v1/admin/roles",
                roleBody("biz_a", List.of(BASIC_QA_USE), identity), admin, 201);
        assignRole(admin, identity, M_MEMBER_A, List.of("biz_a"));

        String member = login("bizMember").path("access_token").asText();
        JsonNode me = switchTenant(member, T_A, 1);
        assertTrue(me.path("permissions").toString().contains(BASIC_QA_USE));

        JsonNode introspected = introspect(member, "langgraph-runtime", false);
        assertTrue(introspected.path("permissions").toString().contains(BASIC_QA_USE),
                introspected.toString());

        JsonNode withContext = introspect(member, "langgraph-runtime", true);
        JsonNode ec = withContext.path("execution_context");
        assertTrue(ec.path("verification_ref").isTextual());

        // 撤掉角色中的业务码：成员修订推进，旧引用复查失配，新内省不再包含业务码
        String admin2 = login("bizAdmin").path("access_token").asText();
        JsonNode identity2 = switchTenant(admin2, T_A, 1);
        call("POST", "/v1/admin/roles/" + role.path("id").asText() + "/permissions", Map.of(
                "permission_codes", List.of(),
                "expected_context", context(identity2),
                "expected_tenant_revision", identity2.path("revisions").path("tenant_auth_revision").asLong()),
                admin2, 200);

        Map<String, Object> recheckBody = new LinkedHashMap<>();
        recheckBody.put("audience", "langgraph-runtime");
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("verification_ref", ec.path("verification_ref").asText());
        ref.put("expected_revisions", json.convertValue(ec.path("revisions"), Map.class));
        recheckBody.put("execution_context", ref);
        JsonNode recheck = callWithBasic("POST", "/v1/internal/identity/introspect", recheckBody, 200);
        assertFalse(recheck.path("active").asBoolean());
        assertFalse(recheck.path("context_matches").asBoolean());
        // 撤权使成员修订推进，原会话权威快照直接失效；语义是"不再放行"，不区分
        // invalid_or_revoked 与 revision_mismatch 两条失败路径。
        assertTrue(List.of("invalid_or_revoked", "revision_mismatch")
                .contains(recheck.path("reason").asText()), recheck.toString());

        String fresh = login("bizMember").path("access_token").asText();
        switchTenant(fresh, T_A, 1);
        assertFalse(introspect(fresh, "langgraph-runtime", false).path("permissions").toString().contains(BASIC_QA_USE));
    }

    @Test
    void disabledRoleAndDisabledMembershipRemoveBusinessAccess() throws Exception {
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        JsonNode role = call("POST", "/v1/admin/roles",
                roleBody("biz_lifecycle", List.of(BASIC_QA_USE), identity), admin, 201);
        assignRole(admin, identity, M_MEMBER_A, List.of("biz_lifecycle"));
        String member = login("bizMember").path("access_token").asText();
        assertTrue(switchTenant(member, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));

        // 角色停用：成员修订推进，旧会话失效，新登录无业务码
        String admin2 = login("bizAdmin").path("access_token").asText();
        JsonNode identity2 = switchTenant(admin2, T_A, 1);
        call("PATCH", "/v1/admin/roles/" + role.path("id").asText(), Map.of(
                "status", "disabled",
                "expected_context", context(identity2),
                "expected_tenant_revision", identity2.path("revisions").path("tenant_auth_revision").asLong()),
                admin2, 200);
        call("GET", "/v1/auth/me", null, member, 401);
        String member2 = login("bizMember").path("access_token").asText();
        assertFalse(switchTenant(member2, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));
        String admin3 = login("bizAdmin").path("access_token").asText();
        JsonNode identity3 = switchTenant(admin3, T_A, 1);
        call("PATCH", "/v1/admin/roles/" + role.path("id").asText(), Map.of(
                "status", "active",
                "expected_context", context(identity3),
                "expected_tenant_revision", identity3.path("revisions").path("tenant_auth_revision").asLong()),
                admin3, 200);
        String member3 = login("bizMember").path("access_token").asText();
        assertTrue(switchTenant(member3, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));

        // 成员停用：旧会话失效，重新登录后不能切到该企业
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.tenant_memberships SET status='disabled' WHERE id='" + M_MEMBER_A + "'");
            con.commit();
        }
        call("GET", "/v1/auth/me", null, member3, 403);
        String member4 = login("bizMember").path("access_token").asText();
        call("POST", "/v1/auth/switch-tenant", Map.of(
                "tenant_id", T_A.toString(), "expected_ctx_version", 1), member4, 403);
        // 恢复成员关系后角色配置仍在，业务码恢复
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.tenant_memberships SET status='active' WHERE id='" + M_MEMBER_A + "'");
            con.commit();
        }
        String member5 = login("bizMember").path("access_token").asText();
        assertTrue(switchTenant(member5, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));
    }

    @Test
    void platformAdminRootLosesBusinessCodeAfterExplicitGrantRevoked() throws Exception {
        // root 的平台管理员身份不构成业务旁路：必须有本企业成员关系与角色授予
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        JsonNode role = call("POST", "/v1/admin/roles",
                roleBody("root_biz", List.of(BASIC_QA_USE), identity), admin, 201);
        UUID rootMembership = UUID.fromString("01932000-0000-4300-8300-000000003009");
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.execute("INSERT INTO iam.tenant_memberships(id,tenant_id,user_id) VALUES ('"
                    + rootMembership + "','" + T_A + "','" + U_ROOT + "')");
            st.execute("INSERT INTO iam.membership_roles(tenant_id,membership_id,role_id,granted_by) VALUES ('"
                    + T_A + "','" + rootMembership + "','" + role.path("id").asText() + "','" + U_ADMIN + "')");
            con.commit();
        }
        long userRevision = userRevision(U_ROOT);
        String passwordHash = passwordHash(U_ROOT);
        String rootSession = login("root").path("access_token").asText();
        JsonNode rootInA = switchTenant(rootSession, T_A, 1);
        assertTrue(rootInA.path("platform_admin").asBoolean());
        assertTrue(rootInA.path("permissions").toString().contains(BASIC_QA_USE));

        String admin2 = login("bizAdmin").path("access_token").asText();
        JsonNode identity2 = switchTenant(admin2, T_A, 1);
        call("POST", "/v1/admin/roles/" + role.path("id").asText() + "/permissions", Map.of(
                "permission_codes", List.of(),
                "expected_context", context(identity2),
                "expected_tenant_revision", identity2.path("revisions").path("tenant_auth_revision").asLong()),
                admin2, 200);
        call("GET", "/v1/auth/me", null, rootSession, 401);
        String rootSession2 = login("root").path("access_token").asText();
        JsonNode afterRevoke = switchTenant(rootSession2, T_A, 1);
        assertTrue(afterRevoke.path("platform_admin").asBoolean());
        assertFalse(afterRevoke.path("permissions").toString().contains(BASIC_QA_USE));

        // 恢复明确授予后正对照
        String admin3 = login("bizAdmin").path("access_token").asText();
        JsonNode identity3 = switchTenant(admin3, T_A, 1);
        call("POST", "/v1/admin/roles/" + role.path("id").asText() + "/permissions", Map.of(
                "permission_codes", List.of(BASIC_QA_USE),
                "expected_context", context(identity3),
                "expected_tenant_revision", identity3.path("revisions").path("tenant_auth_revision").asLong()),
                admin3, 200);
        String rootSession3 = login("root").path("access_token").asText();
        assertTrue(switchTenant(rootSession3, T_A, 1).path("permissions").toString().contains(BASIC_QA_USE));
        // root UUID、口令摘要与平台代次不被授权命令改变
        assertEquals(userRevision, userRevision(U_ROOT));
        assertEquals(passwordHash, passwordHash(U_ROOT));
    }

    @Test
    void writeBoundariesRejectTenantSelfOpenAndGlobalTemplateResourceGrant() throws Exception {
        // 企业请求角色不能自行开通
        try (Connection con = DriverManager.getConnection(appUrl, appUser, appPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context('" + U_ADMIN + "','" + T_A + "',false)");
            assertThrows(Exception.class, () -> st.executeUpdate(
                    "INSERT INTO iam.tenant_entitlements(tenant_id, resource_code, status) "
                            + "VALUES ('" + T_A + "','" + BASIC_QA + "','active')"));
            con.rollback();
        }
        grantEntitlement(rootToken, rootIdentity, T_A, BASIC_QA, 0);
        // 全局企业模板不可携带资源权限（DB 触发器兜底）
        try (Connection con = DriverManager.getConnection(appUrl, appUser, appPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context('" + U_ADMIN + "','" + T_A + "',false)");
            assertThrows(Exception.class, () -> st.executeUpdate(
                    "INSERT INTO iam.role_permissions(role_id, permission_id) "
                            + "SELECT '" + ROLE_TENANT_ADMIN + "', id FROM iam.permissions WHERE code='" + BASIC_QA_USE + "'"));
            con.rollback();
        }
        // 企业 A 未开通分析业务，不能把分析码写入 A 角色
        String admin = login("bizAdmin").path("access_token").asText();
        JsonNode identity = switchTenant(admin, T_A, 1);
        call("POST", "/v1/admin/roles", roleBody("biz_cross", List.of(ANALYSIS_USE), identity), admin, 409);
    }

    // ---------------------------------------------------------------- 辅助

    private void grantEntitlement(String token, JsonNode identity, UUID tenant,
                                  String resourceCode, long expectedRevision) throws Exception {
        long tenantRevision = tenantRevision(tenant);
        call("PUT", "/v1/admin/tenants/" + tenant + "/entitlements/" + resourceCode, Map.of(
                "expected_context", context(identity),
                "expected_revision", expectedRevision,
                "expected_tenant_revision", tenantRevision,
                "status", "active"), token, 200);
    }

    private Map<String, Object> roleBody(String code, List<String> permissions, JsonNode identity) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scope", "tenant");
        body.put("code", code);
        body.put("name", "业务角色 " + code);
        body.put("permission_codes", permissions);
        body.put("expected_context", context(identity));
        body.put("expected_tenant_revision",
                identity.path("revisions").path("tenant_auth_revision").asLong());
        return body;
    }

    private void assignRole(String token, JsonNode identity, UUID membership, List<String> roles)
            throws Exception {
        JsonNode page = call("GET", "/v1/admin/members?tenant_id=" + identity.path("current_tenant").path("id").asText(), null, token, 200);
        JsonNode target = null;
        for (JsonNode row : page.path("items")) {
            if (row.path("id").asText().equals(membership.toString())) {
                target = row;
            }
        }
        assertNotNull(target, "成员不存在: " + membership);
        call("POST", "/v1/admin/members/" + membership + "/roles", Map.of(
                "role_codes", roles,
                "expected_revision", target.path("revision").asLong(),
                "expected_context", context(identity),
                "expected_tenant_revision", identity.path("revisions").path("tenant_auth_revision").asLong()),
                token, 200);
    }

    private long tenantRevision(UUID tenant) throws Exception {
        JsonNode page = call("GET", "/v1/admin/tenants?limit=200", null, rootToken, 200);
        for (JsonNode row : page.path("items")) {
            if (row.path("id").asText().equals(tenant.toString())) {
                return row.path("auth_revision").asLong();
            }
        }
        throw new IllegalStateException("企业不存在: " + tenant);
    }

    private JsonNode entitlementRow(UUID tenant, String resourceCode) throws Exception {
        JsonNode page = call("GET", "/v1/admin/tenants/" + tenant + "/entitlements?limit=200", null, rootToken, 200);
        for (JsonNode row : page.path("items")) {
            if (row.path("resource_code").asText().equals(resourceCode)) {
                return row;
            }
        }
        throw new IllegalStateException("开通记录不存在: " + resourceCode);
    }

    private long userRevision(UUID userId) throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (var rs = st.executeQuery("SELECT auth_revision FROM iam.users WHERE id='" + userId + "'")) {
                rs.next();
                long value = rs.getLong(1);
                con.rollback();
                return value;
            }
        }
    }

    private String passwordHash(UUID userId) throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (var rs = st.executeQuery("SELECT password_hash FROM iam.users WHERE id='" + userId + "'")) {
                rs.next();
                String value = rs.getString(1);
                con.rollback();
                return value;
            }
        }
    }

    private JsonNode findResource(String code) throws Exception {
        JsonNode page = call("GET", "/v1/admin/resources?limit=200", null, rootToken, 200);
        for (JsonNode row : page.path("items")) {
            if (row.path("code").asText().equals(code)) {
                return row;
            }
        }
        throw new IllegalStateException("资源不存在: " + code);
    }

    private JsonNode introspect(String subjectToken, String audience, boolean includeContext)
            throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("audience", audience);
        body.put("subject_token", subjectToken);
        if (includeContext) {
            body.put("include_execution_context", true);
        }
        return callWithBasic("POST", "/v1/internal/identity/introspect", body, 200);
    }

    private JsonNode login(String account) throws Exception {
        return call("POST", "/v1/auth/login", Map.of(
                "account", account, "password", PASSWORD, "realm", "workforce", "audience", "iam-admin"), null, 200);
    }

    private JsonNode switchTenant(String token, UUID tenant, long ctxVersion) throws Exception {
        return call("POST", "/v1/auth/switch-tenant", Map.of(
                "tenant_id", tenant.toString(), "expected_ctx_version", ctxVersion), token, 200);
    }

    private Map<String, Object> context(JsonNode identity) {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("session_id", identity.path("session").path("id").asText());
        ctx.put("tenant_id", identity.path("current_tenant").isNull() ? null
                : identity.path("current_tenant").path("id").asText());
        ctx.put("ctx_version", identity.path("session").path("ctx_version").asLong());
        return ctx;
    }

    private JsonNode call(String method, String path, Object body, String token, int status) throws Exception {
        var request = MockMvcRequestBuilders.request(org.springframework.http.HttpMethod.valueOf(method), path)
                .contentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            request.content(json.writeValueAsString(body));
        }
        var result = mvc.perform(request).andReturn();
        assertEquals(status, result.getResponse().getStatus(),
                method + " " + path + " " + result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode callWithBasic(String method, String path, Object body, int status) throws Exception {
        var request = MockMvcRequestBuilders.request(org.springframework.http.HttpMethod.valueOf(method), path)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)));
        if (body != null) {
            request.content(json.writeValueAsString(body));
        }
        var result = mvc.perform(request).andReturn();
        if (result.getRequest().isAsyncStarted()) {
            result.getAsyncResult(10_000);
            result = mvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andReturn();
        }
        assertEquals(status, result.getResponse().getStatus(),
                method + " " + path + " " + result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String migration(String name) throws Exception {
        return new String(StreamUtils.copyToByteArray(
                new ClassPathResource("db/migration/" + name).getInputStream()), StandardCharsets.UTF_8);
    }

    private void insertUser(Connection con, UUID id, String account, String name, String hash)
            throws Exception {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setString(2, account);
            ps.setString(3, name);
            ps.setString(4, hash);
            ps.executeUpdate();
        }
    }

    private void insertMembership(Connection con, UUID id, UUID tenant, UUID user) throws Exception {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.tenant_memberships(id, tenant_id, user_id) VALUES (?,?,?)")) {
            ps.setObject(1, id);
            ps.setObject(2, tenant);
            ps.setObject(3, user);
            ps.executeUpdate();
        }
    }

    private void insertMembershipRole(Connection con, UUID tenant, UUID membership, UUID role)
            throws Exception {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by) "
                        + "VALUES (?,?,?,?)")) {
            ps.setObject(1, tenant);
            ps.setObject(2, membership);
            ps.setObject(3, role);
            ps.setObject(4, U_ADMIN);
            ps.executeUpdate();
        }
    }
}
