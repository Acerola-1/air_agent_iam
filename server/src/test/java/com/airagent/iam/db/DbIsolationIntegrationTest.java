package com.airagent.iam.db;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C04/C08/C09/C10：真实受限角色 iam_app（NOBYPASSRLS、非 owner）对 iam_test 库的
 * 行级安全、同租户复合外键、无环、最后管理员、授权边界与崩溃窗口 outbox 的反例验证。
 * 连接池固定 1 条物理连接，用于证明 GUC 上下文在提交后不跨请求泄漏。
 */
@SpringBootTest
@ActiveProfiles("it")
class DbIsolationIntegrationTest {

    private static final String HASH =
            "$2b$10$86sNiWmwUpB13rh3OdKpu.wgRVV9HfP1UGIKACH9D0Ro81lpJ1v5y";
    private static final UUID ROLE_TENANT_ADMIN = UUID.fromString("01930000-0000-4000-8000-000000000311");
    private static final UUID ROLE_TENANT_READER = UUID.fromString("01930000-0000-4000-8000-000000000312");
    private static final UUID ROLE_PLATFORM_SUPER = UUID.fromString("01930000-0000-4000-8000-000000000301");
    private static final UUID PERM_MEMBER_READ = UUID.fromString("01930000-0000-4000-8000-000000000101");
    private static final UUID PERM_KNOWLEDGE = UUID.fromString("01930000-0000-4000-8000-000000000201");

    private static final UUID U_PLATFORM = UUID.fromString("01931000-0000-4000-8000-000000000001");
    private static final UUID U_ADMIN_A = UUID.fromString("01931000-0000-4000-8000-000000000002");
    private static final UUID U_MEMBER_A = UUID.fromString("01931000-0000-4000-8000-000000000003");
    private static final UUID U_ADMIN_B = UUID.fromString("01931000-0000-4000-8000-000000000004");
    private static final UUID U_ADMIN_A2 = UUID.fromString("01931000-0000-4000-8000-000000000005");
    private static final UUID T_A = UUID.fromString("01931000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01931000-0000-4100-8100-000000001002");
    private static final UUID D_A_ROOT = UUID.fromString("01931000-0000-4200-8200-000000002001");
    private static final UUID D_A_CHILD = UUID.fromString("01931000-0000-4200-8200-000000002002");
    private static final UUID D_B_ROOT = UUID.fromString("01931000-0000-4200-8200-000000002003");
    private static final UUID M_ADMIN_A = UUID.fromString("01931000-0000-4300-8300-000000003001");
    private static final UUID M_MEMBER_A = UUID.fromString("01931000-0000-4300-8300-000000003002");
    private static final UUID M_ADMIN_B = UUID.fromString("01931000-0000-4300-8300-000000003004");
    private static final UUID M_ADMIN_A2 = UUID.fromString("01931000-0000-4300-8300-000000003005");

    @Autowired
    private DataSource dataSource;

    @Value("${spring.datasource.url}")
    private String appJdbcUrl;
    @Value("${spring.datasource.username}")
    private String appUser;
    @Value("${spring.datasource.password}")
    private String appPassword;
    @Value("${spring.flyway.url}")
    private String migrateJdbcUrl;
    @Value("${spring.flyway.user}")
    private String migrateUser;
    @Value("${spring.flyway.password}")
    private String migratePassword;

    private interface SqlAction {
        void run(Connection con) throws Exception;
    }

    @BeforeEach
    void resetAndSeed() throws Exception {
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement()) {
            st.execute("TRUNCATE iam.resource_catalog, iam.tenants, iam.users CASCADE");
            st.execute("TRUNCATE iam.auth_sessions, iam.audit_logs, iam.outbox, iam.internal_clients, "
                    + "iam.sso_clients, iam.browser_handles, iam.bootstrap_meta CASCADE");
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
        inPlatformTx(con -> {
            for (Object[] u : new Object[][]{
                    {U_PLATFORM, "platboot", "平台引导员"},
                    {U_ADMIN_A, "adminA", "企业A管理员"},
                    {U_MEMBER_A, "memberA", "企业A成员"},
                    {U_ADMIN_B, "adminB", "企业B管理员"},
                    {U_ADMIN_A2, "adminA2", "企业A第二管理员"}}) {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
                    ps.setObject(1, u[0]);
                    ps.setString(2, (String) u[1]);
                    ps.setString(3, (String) u[2]);
                    ps.setString(4, HASH);
                    ps.executeUpdate();
                }
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.tenants(id, code, name, created_by) VALUES (?,?,?,?)"
                            + ",(?,?,?,?)")) {
                ps.setObject(1, T_A);
                ps.setString(2, "TENANT-A");
                ps.setString(3, "测试企业A");
                ps.setObject(4, U_PLATFORM);
                ps.setObject(5, T_B);
                ps.setString(6, "TENANT-B");
                ps.setString(7, "测试企业B");
                ps.setObject(8, U_PLATFORM);
                ps.executeUpdate();
            }
            for (Object[] d : new Object[][]{
                    {D_A_ROOT, T_A, null, "root-a", "A根部门"},
                    {D_A_CHILD, T_A, D_A_ROOT, "child-a", "A子部门"},
                    {D_B_ROOT, T_B, null, "root-b", "B根部门"}}) {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.departments(id, tenant_id, parent_id, code, name) VALUES (?,?,?,?,?)")) {
                    ps.setObject(1, d[0]);
                    ps.setObject(2, d[1]);
                    ps.setObject(3, d[2]);
                    ps.setString(4, (String) d[3]);
                    ps.setString(5, (String) d[4]);
                    ps.executeUpdate();
                }
            }
            for (Object[] m : new Object[][]{
                    {M_ADMIN_A, T_A, U_ADMIN_A, null},
                    {M_MEMBER_A, T_A, U_MEMBER_A, D_A_ROOT},
                    {M_ADMIN_B, T_B, U_ADMIN_B, null}}) {
                insertMembership(con, (UUID) m[0], (UUID) m[1], (UUID) m[2], (UUID) m[3]);
            }
            insertMembershipRole(con, T_A, M_ADMIN_A, ROLE_TENANT_ADMIN);
            insertMembershipRole(con, T_A, M_MEMBER_A, ROLE_TENANT_READER);
            insertMembershipRole(con, T_B, M_ADMIN_B, ROLE_TENANT_ADMIN);
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.user_roles(user_id, role_id, granted_by) VALUES (?,?,?)")) {
                ps.setObject(1, U_PLATFORM);
                ps.setObject(2, ROLE_PLATFORM_SUPER);
                ps.setObject(3, U_PLATFORM);
                ps.executeUpdate();
            }
        });
    }

    @Test
    void c04_seedCatalogCounts() throws Exception {
        inPlatformTx(con -> {
            assertEquals(21L, count(con, "iam.permissions"));
            assertEquals(4L, count(con, "iam.roles"));
            assertEquals(28L, count(con, "iam.role_permissions"));
            assertEquals(1L, count(con, "iam.resource_catalog"));
            try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM iam.role_permissions rp JOIN iam.permissions p "
                            + "ON p.id = rp.permission_id WHERE p.resource_code IS NOT NULL")) {
                rs.next();
                assertEquals(0L, rs.getLong(1), "I1a 种子不预授资源型权限");
            }
        });
    }

    @Test
    void c10_withoutContextSeesNothingAndCannotWrite() throws Exception {
        try (Connection con = dataSource.getConnection()) {
            con.setAutoCommit(true);
            assertEquals(0L, count(con, "iam.tenants"));
            assertEquals(0L, count(con, "iam.departments"));
            assertEquals(0L, count(con, "iam.tenant_memberships"));
            assertSqlState("42501", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.departments(id, tenant_id, code, name) VALUES (?,?,?,?)")) {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setObject(2, T_A);
                    ps.setString(3, "ghost");
                    ps.setString(4, "幽灵部门");
                    ps.executeUpdate();
                }
            });
        }
    }

    @Test
    void c10_machineTablesAreDeniedToAppRoleEvenInContext() throws Exception {
        inPlatformTx(con -> {
            expectDenied(con, "42501", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.sso_clients(client_id, name, secret_digest, callback_url) "
                                + "VALUES ('evil','evil','x','http://127.0.0.1/')")) {
                    ps.executeUpdate();
                }
            });
            expectDenied(con, "42501", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.outbox(kind, payload) VALUES ('redis_delete_keys','{}'::jsonb)")) {
                    ps.executeUpdate();
                }
            });
            expectDenied(con, "42501", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.internal_clients(client_id, name, secret_digest) "
                                + "VALUES ('evil','evil','x')")) {
                    ps.executeUpdate();
                }
            });
        });
    }

    @Test
    void c10_contextAandBIsolationAndPooledConnectionReset() throws Exception {
        inTx(U_ADMIN_A, T_A, con -> {
            assertEquals(2L, count(con, "iam.departments"));
            assertEquals(2L, count(con, "iam.tenant_memberships"));
            expectDenied(con, "42501", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.departments(id, tenant_id, code, name) VALUES (?,?,?,?)")) {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setObject(2, T_B);
                    ps.setString(3, "a-into-b");
                    ps.setString(4, "越权部门");
                    ps.executeUpdate();
                }
            });
        });
        inTx(U_ADMIN_B, T_B, con -> {
            assertEquals(1L, count(con, "iam.departments"), "B 上下文只见 B 部门");
            assertEquals(1L, count(con, "iam.tenant_memberships"));
            try (PreparedStatement ps = con.prepareStatement("SELECT id FROM iam.tenants WHERE id = ?")) {
                ps.setObject(1, T_A);
                try (ResultSet rs = ps.executeQuery()) {
                    assertTrue(!rs.next(), "B 成员不可见 A 企业行");
                }
            }
        });
        try (Connection reused = dataSource.getConnection()) {
            reused.setAutoCommit(true);
            assertEquals(0L, count(reused, "iam.departments"), "提交归还后的池化连接不得残留 A/B 上下文");
        }
    }

    @Test
    void membershipInAnotherTenantDoesNotExposeItsDepartmentsOrPasswordHashes() throws Exception {
        inPlatformTx(con -> {
            try (PreparedStatement statement = con.prepareStatement(
                    "INSERT INTO iam.tenant_memberships(tenant_id, user_id) VALUES (?, ?)")) {
                statement.setObject(1, T_B);
                statement.setObject(2, U_ADMIN_A);
                statement.executeUpdate();
            }
        });
        inTx(U_ADMIN_A, T_A, con -> {
            try (PreparedStatement statement = con.prepareStatement(
                    "SELECT id FROM iam.departments WHERE tenant_id = ?")) {
                statement.setObject(1, T_B);
                try (ResultSet result = statement.executeQuery()) {
                    assertTrue(!result.next());
                }
            }
            expectDenied(con, "42501", () -> {
                try (Statement statement = con.createStatement()) {
                    statement.executeQuery("SELECT password_hash FROM iam.users");
                }
            });
            expectDenied(con, "42501", () -> {
                try (Statement statement = con.createStatement()) {
                    statement.executeUpdate("UPDATE iam.users SET password_hash = 'forbidden'");
                }
            });
        });
    }

    @Test
    void c08_crossTenantCompositeForeignKeysRejected() throws Exception {
        inPlatformTx(con -> {
            expectDenied(con, "23503", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.tenant_memberships(id, tenant_id, user_id, department_id) "
                                + "VALUES (?,?,?,?)")) {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setObject(2, T_A);
                    ps.setObject(3, U_ADMIN_B);
                    ps.setObject(4, D_B_ROOT);
                    ps.executeUpdate();
                }
            });
            expectDenied(con, "23503", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "UPDATE iam.tenant_memberships SET department_id = ? WHERE id = ?")) {
                    ps.setObject(1, D_B_ROOT);
                    ps.setObject(2, M_MEMBER_A);
                    ps.executeUpdate();
                }
            });
            UUID saId = UUID.randomUUID();
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.service_accounts(id, account, name, tenant_id, audiences, expires_at) "
                            + "VALUES (?,?,?,?,?, now() + interval '30 days')")) {
                ps.setObject(1, saId);
                ps.setString(2, "svc-a-it");
                ps.setString(3, "A服务账号");
                ps.setObject(4, T_A);
                ps.setObject(5, new String[]{"langgraph-runtime"});
                ps.executeUpdate();
            }
            expectDenied(con, "23503", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.service_account_permissions(tenant_id, service_account_id, permission_id) "
                                + "VALUES (?,?,?)")) {
                    ps.setObject(1, T_B);
                    ps.setObject(2, saId);
                    ps.setObject(3, PERM_MEMBER_READ);
                    ps.executeUpdate();
                }
            });
        });
    }

    @Test
    void c08_departmentHierarchyRejectsCycle() throws Exception {
        inPlatformTx(con -> {
            UUID dX = UUID.randomUUID();
            UUID dY = UUID.randomUUID();
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.departments(id, tenant_id, code, name) VALUES (?,?,?,?),(?,?,?,?)")) {
                ps.setObject(1, dX);
                ps.setObject(2, T_A);
                ps.setString(3, "cycle-x");
                ps.setString(4, "环X");
                ps.setObject(5, dY);
                ps.setObject(6, T_A);
                ps.setString(7, "cycle-y");
                ps.setString(8, "环Y");
                ps.executeUpdate();
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "UPDATE iam.departments SET parent_id = ? WHERE id = ?")) {
                ps.setObject(1, dY);
                ps.setObject(2, dX);
                ps.executeUpdate();
            }
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "UPDATE iam.departments SET parent_id = ? WHERE id = ?")) {
                    ps.setObject(1, dX);
                    ps.setObject(2, dY);
                    ps.executeUpdate();
                }
            });
        });
    }

    @Test
    void c08_crossTenantCustomRoleRejected() throws Exception {
        UUID bCustom = UUID.randomUUID();
        inTx(null, T_B, con -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.roles(id, code, scope, tenant_id, name) VALUES (?,?, 'tenant', ?, ?)")) {
                ps.setObject(1, bCustom);
                ps.setString(2, "b-custom");
                ps.setObject(3, T_B);
                ps.setString(4, "B自定义角色");
                ps.executeUpdate();
            }
        });
        inPlatformTx(con -> assertSqlState("23514", () -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id) VALUES (?,?,?)")) {
                ps.setObject(1, T_A);
                ps.setObject(2, M_MEMBER_A);
                ps.setObject(3, bCustom);
                ps.executeUpdate();
            }
        }));
    }

    @Test
    void c09_lastTenantAdminIsProtected() throws Exception {
        inPlatformTx(con -> assertSqlState("23514", () -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "DELETE FROM iam.membership_roles WHERE membership_id = ? AND role_id = ?")) {
                ps.setObject(1, M_ADMIN_A);
                ps.setObject(2, ROLE_TENANT_ADMIN);
                ps.executeUpdate();
            }
        }));
        inPlatformTx(con -> assertSqlState("23514", () -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "UPDATE iam.tenant_memberships SET status = 'disabled' WHERE id = ?")) {
                ps.setObject(1, M_ADMIN_A);
                ps.executeUpdate();
            }
        }));
    }

    @Test
    void c09_concurrentLastAdminRemovalLeavesExactlyOne() throws Exception {
        inPlatformTx(con -> {
            insertMembership(con, M_ADMIN_A2, T_A, U_ADMIN_A2, null);
            insertMembershipRole(con, T_A, M_ADMIN_A2, ROLE_TENANT_ADMIN);
        });
        java.util.concurrent.CountDownLatch t1Deleted = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try (Connection c1 = DriverManager.getConnection(appJdbcUrl, appUser, appPassword);
             Connection c2 = DriverManager.getConnection(appJdbcUrl, appUser, appPassword)) {
            c1.setAutoCommit(false);
            c2.setAutoCommit(false);
            setContext(c1, null, null, true);
            setContext(c2, null, null, true);
            try (Statement st = c2.createStatement()) {
                st.execute("SET lock_timeout = '5000'");
            }
            java.util.concurrent.Future<?> f1 = executor.submit(() -> {
                deleteAdminRole(c1, M_ADMIN_A);
                t1Deleted.countDown();
                Thread.sleep(500);
                c1.commit();
                return null;
            });
            java.util.concurrent.Future<?> f2 = executor.submit(() -> {
                assertTrue(t1Deleted.await(10, java.util.concurrent.TimeUnit.SECONDS));
                SQLException failure = assertThrows(SQLException.class,
                        () -> deleteAdminRole(c2, M_ADMIN_A2));
                assertEquals("23514", sqlState(failure), "锁等待后恢复的事务必须被最后管理员保护拒绝");
                c2.rollback();
                return null;
            });
            f1.get(30, java.util.concurrent.TimeUnit.SECONDS);
            f2.get(30, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        inPlatformTx(con -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "SELECT count(DISTINCT m.id) FROM iam.tenant_memberships m "
                            + "JOIN iam.membership_roles mr ON mr.membership_id = m.id "
                            + "JOIN iam.roles r ON r.id = mr.role_id "
                            + "WHERE m.tenant_id = ? AND m.status = 'active' "
                            + "AND r.scope = 'tenant' AND r.code = 'tenant_admin'")) {
                ps.setObject(1, T_A);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    assertEquals(1L, rs.getLong(1));
                }
            }
        });
    }

    private void deleteAdminRole(Connection con, UUID membershipId) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "DELETE FROM iam.membership_roles WHERE membership_id = ? AND role_id = ?")) {
            ps.setObject(1, membershipId);
            ps.setObject(2, ROLE_TENANT_ADMIN);
            ps.executeUpdate();
        }
    }

    @Test
    void c09_lastPlatformSuperAdminIsProtected() throws Exception {
        inPlatformTx(con -> assertSqlState("23514", () -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "DELETE FROM iam.user_roles WHERE user_id = ? AND role_id = ?")) {
                ps.setObject(1, U_PLATFORM);
                ps.setObject(2, ROLE_PLATFORM_SUPER);
                ps.executeUpdate();
            }
        }));
        inPlatformTx(con -> assertSqlState("23514", () -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "UPDATE iam.users SET status = 'disabled' WHERE id = ?")) {
                ps.setObject(1, U_PLATFORM);
                ps.executeUpdate();
            }
        }));
    }

    @Test
    void c08_grantBoundariesAndResourceGate() throws Exception {
        inPlatformTx(con -> {
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.role_permissions(role_id, permission_id, granted_by) VALUES (?,?,?)")) {
                    ps.setObject(1, ROLE_TENANT_ADMIN);
                    ps.setObject(2, PERM_KNOWLEDGE);
                    ps.setObject(3, U_PLATFORM);
                    ps.executeUpdate();
                }
            });
            UUID platformOnlyPerm = UUID.fromString("01930000-0000-4000-8000-000000000002");
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.role_permissions(role_id, permission_id, granted_by) VALUES (?,?,?)")) {
                    ps.setObject(1, ROLE_TENANT_ADMIN);
                    ps.setObject(2, platformOnlyPerm);
                    ps.setObject(3, U_PLATFORM);
                    ps.executeUpdate();
                }
            });
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id) VALUES (?,?,?)")) {
                    ps.setObject(1, T_A);
                    ps.setObject(2, M_MEMBER_A);
                    ps.setObject(3, ROLE_PLATFORM_SUPER);
                    ps.executeUpdate();
                }
            });
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.user_roles(user_id, role_id) VALUES (?,?)")) {
                    ps.setObject(1, U_MEMBER_A);
                    ps.setObject(2, ROLE_TENANT_READER);
                    ps.executeUpdate();
                }
            });
            UUID saId = UUID.randomUUID();
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.service_accounts(id, account, name, tenant_id, audiences, expires_at) "
                            + "VALUES (?,?,?,?,?, now() + interval '30 days')")) {
                ps.setObject(1, saId);
                ps.setString(2, "svc-a-gate");
                ps.setString(3, "A服务账号-资源闸门");
                ps.setObject(4, T_A);
                ps.setObject(5, new String[]{"langgraph-runtime"});
                ps.executeUpdate();
            }
            expectDenied(con, "23514", () -> {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.service_account_permissions(tenant_id, service_account_id, permission_id) "
                                + "SELECT ?, ?, id FROM iam.permissions WHERE code = 'knowledge:lib:air:read'")) {
                    ps.setObject(1, T_A);
                    ps.setObject(2, saId);
                    ps.executeUpdate();
                }
            });
        });
    }

    @Test
    void c16_outboxOnlyAccessibleThroughDefinerFunctions() throws Exception {
        inPlatformTx(con -> {
            try (PreparedStatement ps = con.prepareStatement(
                    "SELECT iam_auth.enqueue_outbox(?, ?::jsonb)")) {
                ps.setString(1, "redis_delete_keys");
                ps.setString(2, "{\"keys\":[\"x\"]}");
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                }
            }
        });
        inPlatformTx(con -> {
            try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(
                    "SELECT id, status FROM iam_auth.claim_due_outbox(16) ORDER BY id")) {
                assertTrue(rs.next());
                long claimed = rs.getLong(1);
                assertEquals("pending", rs.getString(2));
                try (PreparedStatement done = con.prepareStatement(
                        "SELECT iam_auth.complete_outbox(?, false)")) {
                    done.setLong(1, claimed);
                    done.execute();
                }
            }
        });
    }

    private void insertMembership(Connection con, UUID id, UUID tenant, UUID user, UUID department)
            throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.tenant_memberships(id, tenant_id, user_id, department_id) VALUES (?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setObject(2, tenant);
            ps.setObject(3, user);
            ps.setObject(4, department);
            ps.executeUpdate();
        }
    }

    private void insertMembershipRole(Connection con, UUID tenant, UUID membership, UUID role) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by) "
                        + "VALUES (?,?,?,?)")) {
            ps.setObject(1, tenant);
            ps.setObject(2, membership);
            ps.setObject(3, role);
            ps.setObject(4, U_PLATFORM);
            ps.executeUpdate();
        }
    }

    private void inPlatformTx(SqlAction action) throws Exception {
        inTx(null, null, true, action, true);
    }

    private void inTx(UUID user, UUID tenant, SqlAction action) throws Exception {
        inTx(user, tenant, false, action, true);
    }

    private void inTx(UUID user, UUID tenant, boolean platform, SqlAction action, boolean commit) throws Exception {
        try (Connection con = dataSource.getConnection()) {
            con.setAutoCommit(false);
            setContext(con, user, tenant, platform);
            action.run(con);
            if (commit) {
                con.commit();
            }
        }
    }

    private void setContext(Connection con, UUID user, UUID tenant, boolean platform) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "SELECT iam_auth.set_request_context(CAST(NULLIF(?,'') AS uuid), "
                        + "CAST(NULLIF(?,'') AS uuid), ?)")) {
            ps.setString(1, user == null ? "" : user.toString());
            ps.setString(2, tenant == null ? "" : tenant.toString());
            ps.setBoolean(3, platform);
            ps.execute();
        }
    }

    private long count(Connection con, String table) throws SQLException {
        try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery("SELECT count(*) FROM " + table)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private void assertSqlState(String expected, ThrowingRunnable runnable) {
        SQLException ex = assertThrows(SQLException.class, () -> runnable.run());
        assertEquals(expected, sqlState(ex), "实际消息: " + ex.getMessage());
        assertTrue(ex.getMessage() == null || !ex.getMessage().contains(HASH), "异常消息不得包含口令哈希");
    }

    private void expectDenied(Connection con, String expected, ThrowingRunnable runnable) throws Exception {
        try (Statement st = con.createStatement()) {
            st.execute("SAVEPOINT expect_denied");
        }
        try {
            runnable.run();
            throw new AssertionError("期望 SQL 状态 " + expected + "，但语句成功");
        } catch (SQLException e) {
            assertEquals(expected, sqlState(e), "实际消息: " + e.getMessage());
            try (Statement st = con.createStatement()) {
                st.execute("ROLLBACK TO SAVEPOINT expect_denied");
            }
        }
    }

    private String sqlState(Throwable ex) {
        Throwable cur = ex;
        while (cur != null) {
            if (cur instanceof PSQLException p) {
                return p.getSQLState();
            }
            if (cur instanceof SQLException s && s.getSQLState() != null) {
                return s.getSQLState();
            }
            cur = cur.getCause();
        }
        throw new AssertionError("no SQLState on exception", ex);
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
