package com.airagent.iam.ops;

import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.ops.mapper.OpsMapper;
import com.airagent.iam.security.password.PasswordHasher;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StreamUtils;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 一次性运维命令在真实空测试库上的回归：写前冲突、逐企业事务、幂等、审计与旧授权清理。
 */
@SpringBootTest
@ActiveProfiles("it")
class OpsCommandIntegrationTest {

    private static final String PASSWORD = "Ops-It-Only-123!";
    private static final UUID ROOT = UUID.fromString("01933000-0000-4000-8000-000000000001");
    private static final UUID T_A = UUID.fromString("01933000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01933000-0000-4100-8100-000000001002");
    private static final UUID T_SUSPENDED = UUID.fromString("01933000-0000-4100-8100-000000001003");
    private static final UUID ROLE_LEGACY = UUID.fromString("01933000-0000-4400-8400-000000004001");
    private static final UUID SA_LEGACY = UUID.fromString("01933000-0000-4500-8500-000000005001");

    @Autowired OpsMapper mapper;
    @Autowired RequestContextMapper contextMapper;
    @Autowired AdminEventMapper eventMapper;
    @Autowired TransactionTemplate tx;
    @Autowired ObjectMapper json;
    @Autowired PasswordHasher hasher;

    @Value("${spring.flyway.url}") String ownerUrl;
    @Value("${spring.flyway.user}") String ownerUser;
    @Value("${spring.flyway.password}") String ownerPassword;

    private OpsProperties props;
    private OpsService service;

    @BeforeEach
    void seedOwnedTestDatabase() throws Exception {
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
            // 恢复 V2 内置角色/权限，避免本类截断后影响后续测试上下文的 BootstrapRunner
            st.execute(migration("V2__seed_catalog.sql"));
            // V20 已给内置 tenant_admin 模板追加资源授权管理资格；截断后按生产口径补回
            st.execute("INSERT INTO iam.permissions(id,code,name_zh,scope,grantable_to_tenants,sort) "
                    + "VALUES ('01930000-0000-4000-8000-000000000211','tenant:resource:grant','企业资源授权管理','tenant',true,211) ON CONFLICT DO NOTHING");
            st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT r.id,p.id "
                    + "FROM iam.roles r JOIN iam.permissions p ON p.code='tenant:resource:grant' "
                    + "WHERE r.code='tenant_admin' AND r.tenant_id IS NULL ON CONFLICT DO NOTHING");
            st.execute(migration("V24__agent_business_entitlements.sql"));
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
                ps.setObject(1, ROOT);
                ps.setString(2, "root");
                ps.setString(3, "运维测试 root");
                ps.setString(4, hasher.hash(PASSWORD));
                ps.executeUpdate();
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.tenants(id, code, name, status, created_by) VALUES (?,?,?,?,?)")) {
                ps.setObject(1, T_A); ps.setString(2, "OPS-A"); ps.setString(3, "运维甲企业"); ps.setString(4, "active"); ps.setObject(5, ROOT);
                ps.executeUpdate();
                ps.setObject(1, T_B); ps.setString(2, "OPS-B"); ps.setString(3, "运维乙企业"); ps.setString(4, "active"); ps.setObject(5, ROOT);
                ps.executeUpdate();
                ps.setObject(1, T_SUSPENDED); ps.setString(2, "OPS-C"); ps.setString(3, "运维停用企业"); ps.setString(4, "suspended"); ps.setObject(5, ROOT);
                ps.executeUpdate();
            }
            con.commit();
        }
        props = new OpsProperties();
        props.setRootUserId(ROOT.toString());
        props.setExpectedAccount("root");
        props.setTenantIds(T_A + "," + T_B);
        service = new OpsService(mapper, contextMapper, eventMapper, tx, json, props);
    }

    @Test
    void planApplyVerifyAreIdempotentAndKeepCredentials() throws Exception {
        String beforeHash = passwordHash();
        long beforeUserRevision = userRevision();

        Map<String, Object> plan = service.planRootAccess();
        assertEquals(Boolean.TRUE, plan.get("ok"));
        assertEquals(2, ((List<?>) plan.get("tenants")).size());

        Map<String, Object> applied = service.applyRootAccess();
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) applied.get("summary");
        assertEquals(2, summary.get("applied"));
        assertEquals(0, summary.get("failed"));

        Map<String, Object> verified = service.verifyRootAccess();
        assertEquals(Boolean.TRUE, verified.get("ok"), String.valueOf(verified.get("failures")));

        List<Map<String, Object>> first = tenants(applied);
        Map<String, Object> tenantA = first.stream()
                .filter(row -> T_A.toString().equals(row.get("tenant_id"))).findFirst().orElseThrow();
        assertEquals(3, ((List<?>) tenantA.get("entitlements_activated")).size());
        assertEquals(6, ((List<?>) tenantA.get("permissions_added")).size());
        long tenantRevision = ((Number) tenantA.get("tenant_auth_revision")).longValue();
        long membershipRevision = ((Number) tenantA.get("membership_revision")).longValue();

        Map<String, Object> again = service.applyRootAccess();
        @SuppressWarnings("unchecked")
        Map<String, Object> secondSummary = (Map<String, Object>) again.get("summary");
        assertEquals(0, secondSummary.get("applied"));
        assertEquals(2, secondSummary.get("unchanged"));
        Map<String, Object> tenantAAgain = tenants(again).stream()
                .filter(row -> T_A.toString().equals(row.get("tenant_id"))).findFirst().orElseThrow();
        assertEquals(tenantRevision, ((Number) tenantAAgain.get("tenant_auth_revision")).longValue());
        assertEquals(membershipRevision, ((Number) tenantAAgain.get("membership_revision")).longValue());

        assertEquals(2, countAudit("admin.root_access.apply"));
        assertEquals(beforeHash, passwordHash());
        assertEquals(beforeUserRevision, userRevision());

        // 只加当前已注册业务；知识资源与配置保持原样
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.tenant_entitlements WHERE resource_code LIKE 'knowledge:%'")) {
                rs.next();
                assertEquals(0, rs.getInt(1));
            }
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(DISTINCT p.code) FROM iam.role_permissions rp "
                            + "JOIN iam.permissions p ON p.id=rp.permission_id "
                            + "WHERE rp.role_id IN (SELECT id FROM iam.roles WHERE code='tenant_agent_test_admin') "
                            + "AND (p.code LIKE 'agent:business:%:use' OR p.code IN "
                            + "('agent:operations:read','agent:metrics:read','agent:content:read'))")) {
                rs.next();
                assertEquals(6, rs.getInt(1));
            }
            con.rollback();
        }
    }

    @Test
    void writePreflightRejectsMissingOrDisabledRootAndDisabledMembership() throws Exception {
        props.setRootUserId(UUID.randomUUID().toString());
        assertThrows(OpsConflictException.class, service::planRootAccess);

        props.setRootUserId(ROOT.toString());
        props.setExpectedAccount("not-root");
        assertThrows(OpsConflictException.class, service::planRootAccess);

        props.setExpectedAccount("root");
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.users SET status='disabled' WHERE id='" + ROOT + "'");
            con.commit();
        }
        assertThrows(OpsConflictException.class, service::planRootAccess);

        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.executeUpdate("UPDATE iam.users SET status='active' WHERE id='" + ROOT + "'");
            st.executeUpdate("INSERT INTO iam.tenant_memberships(id,tenant_id,user_id,status) VALUES "
                    + "('01933000-0000-4300-8300-000000003001','" + T_A + "','" + ROOT + "','disabled')");
            con.commit();
        }
        Map<String, Object> plan = service.planRootAccess();
        assertEquals(Boolean.FALSE, plan.get("ok"));
        Map<String, Object> applied = service.applyRootAccess();
        assertEquals(Boolean.FALSE, applied.get("ok"));
        assertEquals(0, countAudit("admin.root_access.apply"));
        // 冲突企业在写前停止；另一个企业也不得被写入
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.tenant_memberships WHERE tenant_id='" + T_B + "' AND user_id='" + ROOT + "'")) {
                rs.next();
                assertEquals(0, rs.getInt(1));
            }
            con.rollback();
        }
    }

    @Test
    void applyIsAtomicPerTenantAndCanResumeOnlyUnfinishedTenant() throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.execute("CREATE OR REPLACE FUNCTION iam.it_fail_role_b() RETURNS trigger LANGUAGE plpgsql AS $$ "
                    + "BEGIN IF NEW.tenant_id='" + T_B + "'::uuid THEN RAISE EXCEPTION 'injected role failure'; END IF; RETURN NEW; END $$");
            st.execute("CREATE TRIGGER it_fail_role_b BEFORE INSERT ON iam.roles FOR EACH ROW EXECUTE FUNCTION iam.it_fail_role_b()");
            con.commit();
        }
        try {
            Map<String, Object> applied = service.applyRootAccess();
            @SuppressWarnings("unchecked")
            Map<String, Object> summary = (Map<String, Object>) applied.get("summary");
            assertEquals(1, summary.get("applied"));
            assertEquals(1, summary.get("failed"));
            Map<String, Object> b = tenants(applied).stream()
                    .filter(row -> T_B.toString().equals(row.get("tenant_id"))).findFirst().orElseThrow();
            assertEquals("failed", b.get("status"));
            assertEquals(1, countAudit("admin.root_access.apply"));
        } finally {
            try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
                 Statement st = con.createStatement()) {
                st.execute("DROP TRIGGER IF EXISTS it_fail_role_b ON iam.roles");
                st.execute("DROP FUNCTION IF EXISTS iam.it_fail_role_b()");
            }
        }
        Map<String, Object> resumed = service.applyRootAccess();
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) resumed.get("summary");
        assertEquals(1, summary.get("applied"));
        assertEquals(1, summary.get("unchanged"));
        assertEquals(0, summary.get("failed"));
        Map<String, Object> b = tenants(resumed).stream()
                .filter(row -> T_B.toString().equals(row.get("tenant_id"))).findFirst().orElseThrow();
        assertEquals("applied", b.get("status"));
        assertEquals(Boolean.TRUE, service.verifyRootAccess().get("ok"));
    }

    @Test
    void inventoryAndCleanupRemoveOnlyLegacyAgentMcpObjectsAndAreIdempotent() throws Exception {
        seedLegacyObjects();
        Map<String, Object> inventory = service.inventoryLegacyGrants();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) inventory.get("permissions");
        assertEquals(3, rows.size());
        assertTrue(rows.stream().allMatch(row -> Boolean.TRUE.equals(row.get("exists"))));
        assertEquals(3, ((Number) inventory.get("total_role_edges")).intValue());
        assertEquals(1, ((Number) inventory.get("total_service_account_edges")).intValue());
        assertTrue(((List<?>) inventory.get("dedicated_tables_present")).isEmpty());

        Map<String, Object> cleaned = service.cleanupLegacyGrants();
        assertEquals(3, ((Number) cleaned.get("deleted_count")).intValue());
        assertEquals(3, countAudit("admin.legacy_agent_grants.cleanup"));
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.permissions WHERE code IN ('enterprise:mcp','mcp:binding:read','mcp:binding:manage')")) {
                rs.next();
                assertEquals(0, rs.getInt(1));
            }
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.permissions WHERE code='knowledge:lib:air:read'")) {
                rs.next();
                assertEquals(1, rs.getInt(1));
            }
            try (ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM iam.roles WHERE id='" + ROLE_LEGACY + "'")) {
                rs.next();
                assertEquals(1, rs.getInt(1));
            }
            con.rollback();
        }
        Map<String, Object> again = service.cleanupLegacyGrants();
        assertEquals(0, ((Number) again.get("deleted_count")).intValue());
    }

    @Test
    void cleanupFailureRollsBackEveryDeletion() throws Exception {
        seedLegacyObjects();
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("CREATE OR REPLACE FUNCTION iam.it_fail_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ "
                    + "BEGIN IF OLD.code='mcp:binding:manage' THEN RAISE EXCEPTION 'injected cleanup failure'; END IF; RETURN OLD; END $$");
            st.execute("CREATE TRIGGER it_fail_cleanup BEFORE DELETE ON iam.permissions FOR EACH ROW EXECUTE FUNCTION iam.it_fail_cleanup()");
            con.commit();
        }
        try {
            assertThrows(RuntimeException.class, service::cleanupLegacyGrants);
        } finally {
            try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
                 Statement st = con.createStatement()) {
                st.execute("DROP TRIGGER IF EXISTS it_fail_cleanup ON iam.permissions");
                st.execute("DROP FUNCTION IF EXISTS iam.it_fail_cleanup()");
            }
        }
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.permissions WHERE code IN ('enterprise:mcp','mcp:binding:read','mcp:binding:manage')")) {
                rs.next();
                assertEquals(3, rs.getInt(1));
            }
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.role_permissions WHERE role_id IN "
                            + "('" + ROLE_LEGACY + "','01933000-0000-4400-8400-000000004002')")) {
                rs.next();
                assertEquals(3, rs.getInt(1));
            }
            con.rollback();
        }
    }

    // ---------------------------------------------------------------- 辅助

    private void seedLegacyObjects() throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.execute("INSERT INTO iam.permissions(id,code,name_zh,scope,grantable_to_tenants,resource_code) VALUES "
                    + "('01933000-0000-4600-8600-000000006001','enterprise:mcp','MCP 授权','tenant',true,NULL),"
                    + "('01933000-0000-4600-8600-000000006002','mcp:binding:read','查看授权状态','tenant',true,NULL),"
                    + "('01933000-0000-4600-8600-000000006003','mcp:binding:manage','管理授权绑定','platform',false,NULL)");
            st.execute("INSERT INTO iam.roles(id,scope,tenant_id,code,name,is_builtin) VALUES "
                    + "('" + ROLE_LEGACY + "','tenant','" + T_A + "','legacy_ops','旧模型角色',false),"
                    + "('01933000-0000-4400-8400-000000004002','platform',NULL,'legacy_platform_ops','旧模型平台角色',false)");
            st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT '" + ROLE_LEGACY + "',id "
                    + "FROM iam.permissions WHERE code IN ('enterprise:mcp','mcp:binding:read')");
            st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT "
                    + "'01933000-0000-4400-8400-000000004002',id FROM iam.permissions WHERE code='mcp:binding:manage'");
            st.execute("INSERT INTO iam.service_accounts(id,account,name,tenant_id,audiences,expires_at) VALUES "
                    + "('" + SA_LEGACY + "','legacy-sa','旧模型服务账号','" + T_A + "','{}',now()+interval '30 days')");
            st.execute("INSERT INTO iam.service_account_permissions(tenant_id,service_account_id,permission_id) "
                    + "SELECT '" + T_A + "','" + SA_LEGACY + "',id FROM iam.permissions WHERE code='mcp:binding:read'");
            con.commit();
        }
    }

    private List<Map<String, Object>> tenants(Map<String, Object> result) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) result.get("tenants");
        return rows;
    }

    private int countAudit(String action) throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT COUNT(*) FROM iam.audit_logs WHERE action='" + action + "'")) {
                rs.next();
                int count = rs.getInt(1);
                con.rollback();
                return count;
            }
        }
    }

    private String passwordHash() throws Exception {
        return scalarString("SELECT password_hash FROM iam.users WHERE id='" + ROOT + "'");
    }

    private long userRevision() throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery("SELECT auth_revision FROM iam.users WHERE id='" + ROOT + "'")) {
                rs.next();
                long value = rs.getLong(1);
                con.rollback();
                return value;
            }
        }
    }

    private String scalarString(String sql) throws Exception {
        try (Connection con = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
             Statement st = con.createStatement()) {
            con.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            try (ResultSet rs = st.executeQuery(sql)) {
                rs.next();
                String value = rs.getString(1);
                con.rollback();
                return value;
            }
        }
    }

    private String migration(String name) throws Exception {
        return new String(StreamUtils.copyToByteArray(
                new ClassPathResource("db/migration/" + name).getInputStream()), StandardCharsets.UTF_8);
    }
}
