package com.airagent.iam.auth;

import com.airagent.iam.auth.service.SessionService;

import cn.dev33.satoken.stp.StpUtil;
import com.airagent.iam.auth.dto.ChangePasswordDTO;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.dto.RenewDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.web.error.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PGobject;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.ObjectMapper;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * C05/C06/C07/C11/C16：会话权威用例端到端验证（真实 PG iam_test + 真实 Redis 逻辑库 1）。
 *
 * <p>断言均针对真实进程：Sa-Token 不透明随机令牌 + Redis 会话存在性 + PG 主库权威快照；
 * 无 mock 授权、无 HTTP 200 代替。并发 CAS 用两条真实 iam_app JDBC 连接交错。
 */
@SpringBootTest
@ActiveProfiles("it")
class SessionAuthorityIntegrationTest {

    private static final String PASSWORD = "Test123!Pass";
    private static final String NEW_PASSWORD = "Test123!Pass2";
    private static final UUID ROLE_TENANT_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000311");
    private static final UUID ROLE_TENANT_READER = UUID.fromString(
            "01930000-0000-4000-8000-000000000312");

    private static final UUID U_PLATFORM = UUID.fromString("01931000-0000-4000-8000-000000000001");
    private static final UUID U_ADMIN_A = UUID.fromString("01931000-0000-4000-8000-000000000002");
    private static final UUID U_MEMBER_A = UUID.fromString("01931000-0000-4000-8000-000000000003");
    private static final UUID U_ADMIN_B = UUID.fromString("01931000-0000-4000-8000-000000000004");
    private static final UUID ROLE_PLATFORM_SUPER_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000301");
    private static final UUID T_A = UUID.fromString("01931000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01931000-0000-4100-8100-000000001002");
    private static final UUID M_ADMIN_A = UUID.fromString("01931000-0000-4300-8300-000000003001");
    private static final UUID M_MEMBER_A = UUID.fromString("01931000-0000-4300-8300-000000003002");
    private static final UUID M_ADMIN_B = UUID.fromString("01931000-0000-4300-8300-000000003004");
    private static final UUID M_ADMIN_A_IN_B = UUID.fromString("01931000-0000-4300-8300-000000003006");

    @Autowired
    private SessionService sessionService;
    @Autowired
    private PasswordHasher passwordHasher;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private StringRedisTemplate redis;
    @Autowired
    private OutboxRelay outboxRelay;
    @Autowired
    private ObjectMapper mapper;

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

    private String hash;

    @BeforeEach
    void resetAndSeed() throws Exception {
        hash = passwordHasher.hash(PASSWORD);
        Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
        try (Statement st = con.createStatement()) {
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
        // 播种在单一事务内进行：FORCE RLS 表要求平台上下文，而 local GUC 仅存活于当前事务
        con.setAutoCommit(false);
        try (Statement st = con.createStatement()) {
            st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
            for (Object[] u : new Object[][]{
                    {U_PLATFORM, "platformAdmin", "平台超管（最后管理员保护占位）"},
                    {U_ADMIN_A, "adminA", "企业A管理员"},
                    {U_MEMBER_A, "memberA", "企业A只读成员"},
                    {U_ADMIN_B, "adminB", "企业B管理员"}}) {
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO iam.users(id, account, display_name, password_hash) VALUES (?,?,?,?)")) {
                    ps.setObject(1, u[0]);
                    ps.setString(2, (String) u[1]);
                    ps.setString(3, (String) u[2]);
                    ps.setString(4, hash);
                    ps.executeUpdate();
                }
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.user_roles(user_id, role_id, granted_by) VALUES (?,?,?)")) {
                ps.setObject(1, U_PLATFORM);
                ps.setObject(2, ROLE_PLATFORM_SUPER_ADMIN);
                ps.setObject(3, U_PLATFORM);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO iam.tenants(id, code, name, created_by) VALUES (?,?,?,?),(?,?,?,?)")) {
                int i = 0;
                for (Object[] t : new Object[][]{
                        {T_A, "TENANT-A", "测试企业A"},
                        {T_B, "TENANT-B", "测试企业B"}}) {
                    ps.setObject(++i, t[0]);
                    ps.setString(++i, (String) t[1]);
                    ps.setString(++i, (String) t[2]);
                    ps.setObject(++i, U_ADMIN_A);
                }
                ps.executeUpdate();
            }
            insertMembership(con, M_ADMIN_A, T_A, U_ADMIN_A);
            insertMembership(con, M_MEMBER_A, T_A, U_MEMBER_A);
            insertMembership(con, M_ADMIN_B, T_B, U_ADMIN_B);
            insertMembership(con, M_ADMIN_A_IN_B, T_B, U_ADMIN_A);
            insertMembershipRole(con, T_A, M_ADMIN_A, ROLE_TENANT_ADMIN);
            insertMembershipRole(con, T_A, M_MEMBER_A, ROLE_TENANT_READER);
            insertMembershipRole(con, T_B, M_ADMIN_B, ROLE_TENANT_ADMIN);
            insertMembershipRole(con, T_B, M_ADMIN_A_IN_B, ROLE_TENANT_READER);
            con.commit();
        } finally {
            con.close();
        }
    }

    // ------------------------------------------------------------ C05

    @Test
    void c05_loginMeLogoutLifecycle() {
        String token = login(U_ADMIN_A);
        CurrentSession current = sessionService.requireCurrent(token);
        assertEquals(U_ADMIN_A, current.userId());
        assertEquals(1L, current.ctxVersion());

        IdentityVO me = sessionService.me(token);
        assertTrue(me.active());
        assertEquals("iam.identity.v1", me.schemaVersion());
        assertFalse(me.contextUsable());

        sessionService.logout(token);
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(token));
        assertEquals(401, ex.status());
        // Redis Sa-Token 会话也必须立即消失（Sa-Token 1.46 键缺失时返回 null）
        assertNull(StpUtil.getStpLogic().getLoginIdByToken(token),
                "登出后 Redis 令牌键必须立即删除");
        assertFalse(redis.hasKey(keysFor(token)), "登出后 Redis 键不得残留");
    }

    @Test
    void c05_logoutAllRevokesEverySession() {
        String t1 = login(U_ADMIN_A);
        String t2 = login(U_ADMIN_A);
        assertNotNull(sessionService.requireCurrent(t1));
        assertNotNull(sessionService.requireCurrent(t2));

        sessionService.logoutAll(t1);
        assertRejected(t1);
        assertRejected(t2);
    }

    @Test
    void c05_staleRedisResidueAfterPgRevokeIsStillRejected() {
        String token = login(U_ADMIN_A);
        // 模拟"撤销已落 PG 但 Redis 清理尚未到达"的窗口：直接在 PG 撤销，保留 Redis 键
        revokeInPg(token);
        Object redisLoginId = StpUtil.getStpLogic().getLoginIdByToken(token);
        assertEquals(U_ADMIN_A.toString(), redisLoginId, "前置：Redis 残留键确实还在");

        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(token));
        assertEquals(401, ex.status(), "PG 权威必须在 Redis 残留窗口内拒绝");
        redis.delete(keysFor(token));
    }

    // ------------------------------------------------------------ C06

    @Test
    void c06_disabledUserRejectedOnNextVerification() {
        String token = login(U_MEMBER_A);
        assertNotNull(sessionService.requireCurrent(token));
        migrateUpdate("UPDATE iam.users SET status = 'disabled' WHERE id = '" + U_MEMBER_A + "'");
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireSnapshot(token));
        assertEquals(401, ex.status());
        AuthoritySnapshot snapshot = sessionService.loadSnapshot(digest(token));
        assertEquals("account_disabled", snapshot.status());
    }

    @Test
    void c06_suspendedTenantRejectedOnNextVerification() {
        String token = loginAndSwitch(U_ADMIN_A, T_A);
        assertEquals("ok", sessionService.loadSnapshot(digest(token)).status());
        migrateUpdate("UPDATE iam.tenants SET status = 'suspended' WHERE id = '" + T_A + "'");
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(token));
        assertEquals(403, ex.status());
        assertEquals("tenant_suspended", sessionService.loadSnapshot(digest(token)).status());
    }

    @Test
    void c06_roleRemovalBumpsMembershipRevisionAndRejects() {
        String token = loginAndSwitch(U_MEMBER_A, T_A);
        assertEquals("ok", sessionService.loadSnapshot(digest(token)).status());
        // 撤销只读成员的租户角色 → membership revision +1 → 旧会话下次核验即失效
        migrateUpdate("DELETE FROM iam.membership_roles WHERE membership_id = '" + M_MEMBER_A + "'");
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(token));
        assertEquals(401, ex.status());
        assertEquals("invalid_or_revoked", sessionService.loadSnapshot(digest(token)).status());
    }

    @Test
    void c06_passwordChangeRevokesEveryExistingSession() {
        String current = login(U_ADMIN_A);
        String other = login(U_ADMIN_A);
        sessionService.changePassword(current, new ChangePasswordDTO(PASSWORD, NEW_PASSWORD));

        assertEquals(401, assertThrows(ApiException.class,
                () -> sessionService.requireCurrent(current)).status(), "改密也必须撤销当前会话");
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(other));
        assertEquals(401, ex.status(), "其他会话必须因用户授权代次推进被拒");

        // 新口令可登录、旧口令被拒
        ApiException bad = assertThrows(ApiException.class,
                () -> sessionService.login(
                        new LoginDTO("adminA", PASSWORD, "workforce", "iam-admin")));
        assertEquals(401, bad.status());
        String renewed = loginWith(U_ADMIN_A, NEW_PASSWORD);
        assertNotNull(sessionService.requireCurrent(renewed));
    }

    // ------------------------------------------------------------ C07

    @Test
    void c07_switchTenantCasHappyPathAndStaleCtx() {
        String token = login(U_ADMIN_A);
        IdentityVO afterA = sessionService.switchTenant(token,
                new SwitchTenantDTO(T_A.toString(), 1L));
        assertEquals(2L, afterA.contextVersion());
        assertEquals(T_A.toString(), afterA.currentTenant().id());
        assertTrue(afterA.contextUsable());
        assertTrue(afterA.tenantRoles().stream().anyMatch(r -> "tenant_admin".equals(r.code())));

        ApiException stale = assertThrows(ApiException.class, () -> sessionService.switchTenant(token,
                new SwitchTenantDTO(T_B.toString(), 1L)));
        assertEquals(409, stale.status());
        assertEquals("context_changed", stale.code());

        IdentityVO afterB = sessionService.switchTenant(token,
                new SwitchTenantDTO(T_B.toString(), 2L));
        assertEquals(3L, afterB.contextVersion());
        assertEquals(T_B.toString(), afterB.currentTenant().id());

        // A→B→A：迟到的 B 基线（expected=2）必须被拒，只有最新 ctx=3 可切
        assertThrows(ApiException.class, () -> sessionService.switchTenant(token,
                new SwitchTenantDTO(T_A.toString(), 2L)));
        IdentityVO backToA = sessionService.switchTenant(token,
                new SwitchTenantDTO(T_A.toString(), 3L));
        assertEquals(4L, backToA.contextVersion());
        assertEquals(T_A.toString(), backToA.currentTenant().id());
    }

    @Test
    void c07_switchToNonMemberTenantForbidden() {
        String token = login(U_MEMBER_A);
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.switchTenant(token,
                new SwitchTenantDTO(T_B.toString(), 1L)));
        assertEquals(403, ex.status());
    }

    @Test
    void c07_concurrentSwitchWithSameExpectedExactlyOneWins() throws Exception {
        String token = login(U_ADMIN_A);
        UUID sessionId = sessionService.requireCurrent(token).sessionId();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<String> f1 = pool.submit(() -> rawSwitch(sessionId, T_B, 1L, start));
            Future<String> f2 = pool.submit(() -> rawSwitch(sessionId, T_A, 1L, start));
            start.countDown();
            String r1 = f1.get(20, TimeUnit.SECONDS);
            String r2 = f2.get(20, TimeUnit.SECONDS);
            long wins = List.of(r1, r2).stream().filter("ok"::equals).count();
            long conflicts = List.of(r1, r2).stream().filter("P0010"::equals).count();
            assertEquals(1L, wins, "同一 expected 并发切企业必须恰有一个成功");
            assertEquals(1L, conflicts, "落败者必须收到版本冲突");
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------ C16

    @Test
    void c16_renewAdvancesIdleAndRejectsStaleCtx() {
        String token = login(U_ADMIN_A);
        var timers = sessionService.renew(token, new RenewDTO(1L));
        assertNotNull(timers.absoluteExpiresAt());
        assertNotNull(timers.idleExpiresAt());
        ApiException stale = assertThrows(ApiException.class,
                () -> sessionService.renew(token, new RenewDTO(99L)));
        assertEquals(409, stale.status());
    }

    @Test
    void c16_expiredSessionCannotBeResurrectedByRenew() {
        String token = login(U_ADMIN_A);
        migrateUpdate("UPDATE iam.auth_sessions SET expires_at = now() - interval '1 minute', "
                + "idle_expires_at = now() - interval '1 minute' WHERE token_digest = '"
                + digest(token) + "'");
        ApiException ex = assertThrows(ApiException.class,
                () -> sessionService.renew(token, new RenewDTO(1L)));
        assertEquals(401, ex.status(), "过期会话续期必须被拒，不可复活");
    }

    // ------------------------------------------------------------ C11

    @Test
    void c11_auditFailureRollsBackRevocationAndOutbox() throws Exception {
        String token = login(U_ADMIN_A);
        UUID sessionId = sessionService.requireCurrent(token).sessionId();
        String digest = digest(token);
        try (Connection con = DriverManager.getConnection(appJdbcUrl, appUser, appPassword)) {
            con.setAutoCommit(false);
            setContext(con, U_ADMIN_A, T_A, false);
            try (Statement st = con.createStatement()) {
                st.execute("SET lock_timeout = '5000'");
                st.execute("SELECT iam_auth.revoke_session('" + sessionId + "', 'test.audit-fail')");
                st.execute("SELECT iam_auth.enqueue_outbox('redis_delete_keys', "
                        + "'{\"keys\":[\"Authorization:probe\"]}'::jsonb)");
                // 上下文是 A，却试图写 B 企业审计 → FORCE RLS WITH CHECK 拒绝
                SQLException denied = assertThrows(SQLException.class, () -> st.execute(
                        "SELECT iam_auth.write_audit('" + T_B + "', '" + U_ADMIN_A
                                + "', 'human', 'auth.logout', 'auth_session', '" + sessionId
                                + "', '{}'::jsonb, 'req-it')"));
                assertEquals("42501", sqlState(denied));
                con.rollback();
            }
        }
        // 回滚后：会话仍 active、outbox 无探针行（授权修改与审计/outbox 同事务）
        // 用 migrate 连接复核，避免 RLS 无上下文可见性干扰断言
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement()) {
            try (ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM iam.auth_sessions WHERE token_digest = '"
                            + digest + "' AND status = 'active'")) {
                rs.next();
                assertEquals(1L, rs.getLong(1));
            }
            try (ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM iam.outbox WHERE payload::text LIKE '%probe%'")) {
                rs.next();
                assertEquals(0L, rs.getLong(1));
            }
        }
    }

    @Test
    void c11_outboxRelayDeletesRedisKeyAndMarksDone() {
        String token = login(U_ADMIN_B);
        sessionService.logout(token);
        // 立刻同步驱动一次中继（避免等待 1s 调度），幂等：已完成则申领为空
        outboxRelay.relay();
        // iam_app 无 outbox 表 SELECT 授权，且可能与 1s 调度竞争；用 migrate 连接按 payload 定位
        String status;
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             PreparedStatement ps = con.prepareStatement(
                     "SELECT status FROM iam.outbox WHERE payload::text LIKE ? "
                             + "ORDER BY id DESC LIMIT 1")) {
            ps.setString(1, "%" + digest(token) + "%");
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "logout 必须写入 outbox 行");
                status = rs.getString(1);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        assertEquals("done", status);
        assertFalse(redis.hasKey(keysFor(token)), "Redis 会话键必须被 outbox 中继清理");
        assertRejected(token);
    }

    @Test
    void c11_outboxFailureIsRetriedWithBackoffThenCompletes() {
        ObjectMapper realMapper = mapper;
        com.airagent.iam.auth.mapper.InfrastructureMapper eventMapper =
                mock(com.airagent.iam.auth.mapper.InfrastructureMapper.class);
        StringRedisTemplate mockRedis = mock(StringRedisTemplate.class);
        var row = new com.airagent.iam.auth.entity.OutboxEventDO(4242L, "redis_delete_keys",
                "{\"keys\":[\"Authorization:abc\"]}", 1);
        when(eventMapper.claimOutbox(16)).thenReturn(List.of(row), List.of(row));
        when(mockRedis.delete(anyList()))
                .thenThrow(new org.springframework.data.redis.RedisConnectionFailureException("boom"))
                .thenReturn(1L);

        OutboxRelay relay = new OutboxRelay(eventMapper, mockRedis, realMapper);
        relay.relay();
        verify(eventMapper).requeueOutbox(4242L, 10);
        verify(eventMapper, never()).completeOutbox(4242L);
        relay.relay();
        verify(eventMapper).completeOutbox(4242L);
    }

    @Test
    void c05_identitySerializationContainsNoSecretMaterial() throws Exception {
        String token = loginAndSwitch(U_ADMIN_A, T_A);
        IdentityVO identity = sessionService.me(token);
        String json = mapper.writeValueAsString(identity);
        assertFalse(json.contains("password"), "身份响应不得包含口令字段");
        assertFalse(json.contains("$2b$"), "身份响应不得包含口令哈希");
        assertFalse(json.contains("token_digest"), "身份响应不得包含令牌摘要");
        assertTrue(json.contains("\"revisions\""));
    }

    // ------------------------------------------------------------ helpers

    private String login(UUID userId) {
        return loginWith(userId, PASSWORD);
    }

    private String loginWith(UUID userId, String password) {
        String account = switch (userId.toString()) {
            case "01931000-0000-4000-8000-000000000003" -> "memberA";
            case "01931000-0000-4000-8000-000000000004" -> "adminB";
            default -> "adminA";
        };
        LoginVO result = sessionService.login(
                new LoginDTO(account, password, "workforce", "iam-admin"));
        return result.accessToken();
    }

    private String loginAndSwitch(UUID userId, UUID tenant) {
        String token = login(userId);
        sessionService.switchTenant(token, new SwitchTenantDTO(tenant.toString(), 1L));
        return token;
    }

    private void assertRejected(String token) {
        ApiException ex = assertThrows(ApiException.class, () -> sessionService.requireCurrent(token));
        assertEquals(401, ex.status());
    }

    private String digest(String rawToken) {
        return com.airagent.iam.security.token.OpaqueTokens.digest(rawToken);
    }

    private String keysFor(String rawToken) {
        // 与 StpLogic.splicingKeyTokenValue 同构：Authorization:<loginType>:token:<digest>
        return "Authorization:login:token:" + digest(rawToken);
    }

    private void revokeInPg(String token) {
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement()) {
            st.execute("UPDATE iam.auth_sessions SET status = 'revoked', revoked_at = now(), "
                    + "revoke_reason = 'test.manual' WHERE token_digest = '" + digest(token) + "'");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 以 owner 角色执行管理侧 DML。tenants/memberships/membership_roles 为 FORCE RLS，
     * 即使是 owner 无上下文时也看不到行（UPDATE/DELETE 静默命中 0 行），
     * 因此必须在同一事务内显式建立平台上下文再提交。
     */
    private void migrateUpdate(String sql) {
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword)) {
            con.setAutoCommit(false);
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                int affected = st.executeUpdate(sql);
                assertTrue(affected > 0, "管理侧 DML 必须命中行，实际 " + affected + " 行：" + sql);
                con.commit();
            } catch (SQLException e) {
                con.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 两条真实 iam_app 连接上的并发 CAS 切企业：行锁串行化后版本比较决定唯一赢家。
     * FORCE RLS 对 SECURITY DEFINER 的 owner 角色同样生效，因此事务内必须先以会话主体
     * （adminA + 目标企业）建立请求上下文，否则成员校验行不可见。
     */
    private String rawSwitch(UUID sessionId, UUID tenant, long expected, CountDownLatch start) {
        try (Connection con = DriverManager.getConnection(appJdbcUrl, appUser, appPassword)) {
            start.await(10, TimeUnit.SECONDS);
            con.setAutoCommit(false);
            setContext(con, U_ADMIN_A, tenant, false);
            try (Statement st = con.createStatement()) {
                st.execute("SET lock_timeout = '5000'");
                try (ResultSet rs = st.executeQuery("SELECT ctx_version FROM "
                        + "iam_auth.switch_session_context('" + sessionId + "', '" + tenant
                        + "', " + expected + ")")) {
                    assertTrue(rs.next(), "成功路径必须返回新 ctx 版本");
                }
                con.commit();
                return "ok";
            }
        } catch (SQLException e) {
            String state = sqlState(e);
            return state != null ? state : "error";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "interrupted";
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

    private PGobject pgObject(String json) {
        try {
            PGobject pg = new PGobject();
            pg.setType("jsonb");
            pg.setValue(json);
            return pg;
        } catch (SQLException e) {
            throw new RuntimeException(e);
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
        return null;
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
}
