package com.airagent.iam.admin;

import com.airagent.iam.admin.dto.CreateDepartmentDTO;
import com.airagent.iam.admin.dto.CreateMembershipDTO;
import com.airagent.iam.admin.dto.CreateRoleDTO;
import com.airagent.iam.admin.dto.CreateTenantDTO;
import com.airagent.iam.admin.dto.CreateUserDTO;
import com.airagent.iam.admin.vo.DepartmentVO;
import com.airagent.iam.admin.vo.GrantableTreeVO;
import com.airagent.iam.admin.dto.MemberRolesDTO;
import com.airagent.iam.admin.vo.MemberVO;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.admin.dto.PlatformRolesDTO;
import com.airagent.iam.admin.dto.ResetPasswordDTO;
import com.airagent.iam.admin.dto.RolePermissionsDTO;
import com.airagent.iam.admin.vo.RoleVO;
import com.airagent.iam.admin.vo.TenantVO;
import com.airagent.iam.admin.dto.UpdateDepartmentDTO;
import com.airagent.iam.admin.dto.UpdateMembershipDTO;
import com.airagent.iam.admin.dto.UpdateTenantDTO;
import com.airagent.iam.admin.dto.UpdateUserDTO;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.admin.service.TenantAdminService;
import com.airagent.iam.admin.service.UserAdminService;
import com.airagent.iam.admin.service.RoleAdminService;
import com.airagent.iam.audit.service.AuditService;
import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.security.internal.InternalClientAuthenticator;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.serviceaccount.service.ServiceAccountService;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountDetailVO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;
import com.airagent.iam.serviceaccount.dto.UpdateServiceAccountDTO;
import com.airagent.iam.web.error.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 第5组：平台/企业管理 API 的真实链路测试（真实 PG iam_test + Redis DB1，无 mock）。
 * 覆盖权限门、租户隔离、可授边界、乐观修订、最后管理员、同事务审计与服务账号停用即时生效。
 */
@SpringBootTest
@ActiveProfiles("it")
class AdminApiIntegrationTest {

    private static final String PASSWORD = "Test123!Pass";
    private static final String NEW_PASSWORD = "NewPass456!Word";
    private static final String KNOWLEDGE_CLIENT = "it-knowledge-client";
    private static final String KNOWLEDGE_SECRET = "knowledge-secret-0123456789abcdef0123456";
    private static final String KNOWLEDGE_AUD = "knowledge";

    private static final UUID U_PLATFORM = UUID.fromString("01931000-0000-4000-8000-000000000001");
    private static final UUID U_ADMIN_A = UUID.fromString("01931000-0000-4000-8000-000000000002");
    private static final UUID U_MEMBER_A = UUID.fromString("01931000-0000-4000-8000-000000000003");
    private static final UUID ROLE_PLATFORM_SUPER_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000301");
    private static final UUID ROLE_PLATFORM_AUDITOR = UUID.fromString(
            "01930000-0000-4000-8000-000000000302");
    private static final UUID ROLE_TENANT_ADMIN = UUID.fromString(
            "01930000-0000-4000-8000-000000000311");
    private static final UUID ROLE_TENANT_READER = UUID.fromString(
            "01930000-0000-4000-8000-000000000312");
    private static final UUID T_A = UUID.fromString("01931000-0000-4100-8100-000000001001");
    private static final UUID T_B = UUID.fromString("01931000-0000-4100-8100-000000001002");
    private static final UUID M_ADMIN_A = UUID.fromString("01931000-0000-4300-8300-000000003001");
    private static final UUID M_MEMBER_A = UUID.fromString("01931000-0000-4300-8300-000000003002");
    private static final UUID M_ADMIN_A_IN_B = UUID.fromString("01931000-0000-4300-8300-000000003006");

    @Autowired
    private UserAdminService userAdmin;
    @Autowired
    private TenantAdminService tenantAdmin;
    @Autowired
    private RoleAdminService roleAdmin;
    @Autowired
    private AuditService auditAdmin;
    @Autowired
    private ServiceAccountService serviceAccountService;
    @Autowired
    private SessionService sessionService;
    @Autowired
    private InternalClientAuthenticator authenticator;
    @Autowired
    private IntrospectionService introspectionService;
    @Autowired
    private PasswordHasher passwordHasher;
    @Autowired
    private ObjectMapper mapper;

    @Value("${spring.flyway.url}")
    private String migrateJdbcUrl;
    @Value("${spring.flyway.user}")
    private String migrateUser;
    @Value("${spring.flyway.password}")
    private String migratePassword;

    private InternalClient knowledge;

    @BeforeEach
    void resetAndSeed() throws Exception {
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
            try (Statement st = con.createStatement()) {
                st.execute("SELECT iam_auth.set_request_context(NULL, NULL, true)");
                seedUsers(con, hash);
                seedTenantsAndMembers(con);
                seedInternalClient(con);
                con.commit();
            }
        }
        knowledge = new InternalClient(KNOWLEDGE_CLIENT, "knowledge",
                List.of("identity:introspect"), List.of(KNOWLEDGE_AUD), "active");
    }

    // ================================================================ 5.1 用户/企业

    @Test
    void userLifecyclePasswordResetAndLastAdmin() {
        CurrentSession platform = platformSession();

        // 建档 201 + 弱口令 400 + 重复账号 409
        UserVO created = userAdmin.create(platform,
                new CreateUserDTO("newhire01", "新员工甲", NEW_PASSWORD));
        assertNotNull(created.id());
        assertEquals(0L, created.authRevision());
        ApiException weak = assertThrows(ApiException.class, () -> userAdmin.create(platform,
                new CreateUserDTO("weakpw01", "弱口令", "short")));
        assertEquals(400, weak.status());
        ApiException dup = assertThrows(ApiException.class, () -> userAdmin.create(platform,
                new CreateUserDTO("newhire01", "重复账号", NEW_PASSWORD)));
        assertEquals(409, dup.status());

        // 详情/搜索分页
        UserVO fetched = userAdmin.get(platform, created.id());
        assertEquals("新员工甲", fetched.displayName());
        PageVO<UserVO> page = userAdmin.list(platform, 200, null, "newhire");
        assertTrue(page.items().stream().anyMatch(u -> u.id().equals(created.id())));
        assertNull(page.nextCursor());

        // 租户管理员不得访问平台用户线
        CurrentSession adminA = switchedSession("adminA", T_A, 1L);
        ApiException forbidden = assertThrows(ApiException.class,
                () -> userAdmin.list(adminA, null, null, null));
        assertEquals(403, forbidden.status());

        // 改资料 + 乐观修订：错误代次 409
        ApiException stale = assertThrows(ApiException.class, () -> userAdmin.update(platform,
                created.id(), new UpdateUserDTO("新员工甲-改", null, 999L)));
        assertEquals(409, stale.status());
        UserVO renamed = userAdmin.update(platform, created.id(),
                new UpdateUserDTO("新员工甲-改", null, 0L));
        assertEquals(0L, renamed.authRevision(), "仅改资料不推进授权修订");

        // 重置密码即时撤销：旧会话立即失效，旧口令不可登录，新口令可用
        String oldToken = login("newhire01", NEW_PASSWORD);
        assertNotNull(sessionService.requireCurrent(oldToken));
        userAdmin.resetPassword(platform, created.id(),
                new ResetPasswordDTO("ResetPass789!", renamed.authRevision()));
        ApiException killed = assertThrows(ApiException.class,
                () -> sessionService.requireCurrent(oldToken));
        assertEquals(401, killed.status());
        ApiException oldPw = assertThrows(ApiException.class,
                () -> login("newhire01", NEW_PASSWORD));
        assertEquals(401, oldPw.status());
        assertNotNull(login("newhire01", "ResetPass789!"));

        // 平台角色：可授审计员；撤掉最后一个超管被 DB 触发器拒绝（23514→409）
        UserVO withAuditor = userAdmin.replacePlatformRoles(platform, created.id(),
                new PlatformRolesDTO(List.of("platform_auditor"), null));
        assertTrue(withAuditor.platformRoles().contains("platform_auditor"));
        ApiException lastAdmin = assertThrows(ApiException.class, () -> userAdmin.replacePlatformRoles(
                platform, U_PLATFORM.toString(), new PlatformRolesDTO(List.of(), null)));
        assertEquals(409, lastAdmin.status());
    }

    @Test
    void tenantCreateStatusAndRevision() {
        CurrentSession platform = platformSession();
        TenantVO c = tenantAdmin.createTenant(platform,
                new CreateTenantDTO("TENANT-C", "测试企业C"));
        assertNotNull(c.id());
        assertEquals(1L, c.authRevision());
        assertTrue(sessionService.tenants(platform).stream().anyMatch(item -> c.id().equals(item.tenantId())));
        ApiException stale = assertThrows(ApiException.class, () -> tenantAdmin.updateTenant(
                platform, c.id(), new UpdateTenantDTO(null, "suspended", 42L)));
        assertEquals(409, stale.status());
        TenantVO suspended = tenantAdmin.updateTenant(platform, c.id(),
                new UpdateTenantDTO(null, "suspended", 1L));
        assertEquals("suspended", suspended.status());
    }

    // ================================================================ 5.2 成员/部门

    @Test
    void memberIsolationNoAutoMergeAndOptimisticRevision() {
        CurrentSession adminA = switchedSession("adminA", T_A, 1L);
        CurrentSession adminB = switchedSession("adminA", T_B, 1L);

        // B 上下文不得操作 A 的成员/显式带 A tenant 写
        ApiException crossWrite = assertThrows(ApiException.class, () -> tenantAdmin.createMembership(
                adminB, new CreateMembershipDTO(T_A.toString(), null, "hack01", "越权",
                        NEW_PASSWORD, null, null)));
        assertEquals(403, crossWrite.status());
        ApiException crossRead = assertThrows(ApiException.class,
                () -> tenantAdmin.listMembers(adminB, T_A.toString(), null, null));
        assertEquals(403, crossRead.status());

        // A 内显式建档 + 关联角色
        MemberVO member = tenantAdmin.createMembership(adminA,
                new CreateMembershipDTO(null, null, "newhireA", "企业A新员工",
                        NEW_PASSWORD, null, List.of("tenant_reader")));
        assertNotNull(member.id());
        assertTrue(member.roles().contains("tenant_reader"));
        // 建成员时授予角色已触发一次成员修订推进（1 → 2）
        assertEquals(2L, member.revision());

        // 重复成员 409
        ApiException dupMember = assertThrows(ApiException.class, () -> tenantAdmin.createMembership(
                adminA, new CreateMembershipDTO(null, member.user().id(), null, null,
                        null, null, null)));
        assertEquals(409, dupMember.status());

        // 已存在账号不带 user_id：拒绝按同名自动合并（409）
        ApiException noMerge = assertThrows(ApiException.class, () -> tenantAdmin.createMembership(
                adminA, new CreateMembershipDTO(null, null, "memberA", null,
                        null, null, null)));
        assertEquals(409, noMerge.status());

        // 角色全量替换：错误修订 409，正确修订成功（触发器推成员修订）
        ApiException stale = assertThrows(ApiException.class, () -> tenantAdmin.replaceMemberRoles(
                adminA, member.id(), new MemberRolesDTO(List.of("tenant_admin"), 99L)));
        assertEquals(409, stale.status());
        MemberVO promoted = tenantAdmin.replaceMemberRoles(adminA, member.id(),
                new MemberRolesDTO(List.of("tenant_admin"), 2L));
        // 全量替换 = DELETE 触发一次 + INSERT 触发一次：2 → 4
        assertEquals(4L, promoted.revision());

        // 停用成员后，该成员在该企业的实时核验立即失败
        String memberToken = login("newhireA", NEW_PASSWORD);
        sessionService.switchTenant(memberToken, new SwitchTenantDTO(T_A.toString(), 1L));
        assertNotNull(sessionService.requireCurrent(memberToken));
        tenantAdmin.updateMembership(adminA, member.id(),
                new UpdateMembershipDTO(null, "disabled", 4L));
        ApiException disabled = assertThrows(ApiException.class,
                () -> sessionService.requireCurrent(memberToken));
        assertEquals(403, disabled.status());
    }

    @Test
    void departmentTreeRejectsCycleAndCrossTenant() {
        CurrentSession adminA = switchedSession("adminA", T_A, 1L);
        DepartmentVO d1 = tenantAdmin.createDepartment(adminA, T_A.toString(),
                new CreateDepartmentDTO("D1", "部门一", null));
        DepartmentVO d2 = tenantAdmin.createDepartment(adminA, T_A.toString(),
                new CreateDepartmentDTO("D2", "部门二", d1.id()));
        // 让 d1 挂到 d2 下 → d1→d2→d1 成环（reject_department_cycle 触发器）
        ApiException cycle = assertThrows(ApiException.class, () -> tenantAdmin.updateDepartment(
                adminA, d1.id(), new UpdateDepartmentDTO(null, d2.id(), null)));
        assertEquals(409, cycle.status());
        // 树可查（分页）
        PageVO<DepartmentVO> page = tenantAdmin.listDepartments(adminA, T_A.toString(), 200, null);
        assertEquals(2, page.items().size());
    }

    // ================================================================ 5.3 角色/可授树

    @Test
    void customRoleBoundaryBuiltinProtectionAndGrantableTree() {
        CurrentSession adminA = switchedSession("adminA", T_A, 1L);

        // 企业自定义角色：可授企业码；挂平台码/资源码被边界触发器拒绝（23514→409）
        RoleVO custom = roleAdmin.createRole(adminA, new CreateRoleDTO(
                "tenant", "custom-auditor", "企业自定义审计", null, List.of("tenant:audit:read")));
        assertEquals("tenant", custom.scope());
        ApiException platformCode = assertThrows(ApiException.class, () -> roleAdmin.replacePermissions(
                adminA, custom.id(), new RolePermissionsDTO(List.of("platform:user:read"))));
        assertEquals(409, platformCode.status());
        RoleVO replaced = roleAdmin.replacePermissions(adminA, custom.id(),
                new RolePermissionsDTO(List.of("tenant:member:read", "tenant:audit:read")));
        assertEquals(2, replaced.permissionCodes().size());

        // 内置角色不可改
        ApiException builtin = assertThrows(ApiException.class, () -> roleAdmin.updateRole(
                adminA, ROLE_TENANT_ADMIN.toString(),
                new com.airagent.iam.admin.dto.UpdateRoleDTO("改名", null, null)));
        assertEquals(403, builtin.status());

        // 可授树：企业管理员只见企业组，且资源型权限缺席
        GrantableTreeVO tenantTree = roleAdmin.grantableTree(adminA);
        assertEquals(1, tenantTree.groups().size());
        assertEquals("tenant", tenantTree.groups().get(0).scope());
        assertTrue(tenantTree.groups().get(0).permissions().stream()
                .noneMatch(l -> l.code().startsWith("platform:")));
        assertTrue(tenantTree.groups().get(0).permissions().stream()
                .noneMatch(l -> l.resourceCode() != null));

        // 平台视角有两组且不含资源型叶节点；权限目录对企业主体屏蔽平台码
        GrantableTreeVO platformTree = roleAdmin.grantableTree(platformSession());
        assertEquals(2, platformTree.groups().size());
        assertTrue(platformTree.groups().stream()
                .flatMap(g -> g.permissions().stream())
                .noneMatch(l -> "knowledge:lib:air:read".equals(l.code())));
        var tenantCatalog = roleAdmin.listPermissions(adminA);
        assertTrue(tenantCatalog.stream().noneMatch(p -> p.code().startsWith("platform:")));
    }

    // ================================================================ 5.4 审计隔离

    @Test
    void limitedRoleWriterCannotPromoteSelfOrAttachAnUnrelatedGlobalUser() {
        CurrentSession admin = switchedSession("adminA", T_A, 1L);
        roleAdmin.createRole(admin, new CreateRoleDTO("tenant", "limited-writer", "有限授权人", null,
                List.of("tenant:role:write", "tenant:member:write")));
        tenantAdmin.replaceMemberRoles(admin, M_MEMBER_A.toString(),
                new MemberRolesDTO(List.of("limited-writer"), 2L));
        CurrentSession limited = switchedSession("memberA", T_A, 1L);
        ApiException promotion = assertThrows(ApiException.class, () -> tenantAdmin.replaceMemberRoles(
                limited, M_MEMBER_A.toString(), new MemberRolesDTO(List.of("tenant_admin"), null)));
        assertEquals(403, promotion.status());
        ApiException createAdmin = assertThrows(ApiException.class, () -> tenantAdmin.createMembership(limited,
                new CreateMembershipDTO(null, null, "forbiddenhire", "越界授予", NEW_PASSWORD,
                        null, List.of("tenant_admin"))));
        assertEquals(403, createAdmin.status());
        ApiException attach = assertThrows(ApiException.class, () -> tenantAdmin.createMembership(limited,
                new CreateMembershipDTO(null, U_PLATFORM.toString(), null, null, null, null, null)));
        assertEquals(403, attach.status());
    }

    @Test
    void disablingGlobalUserCannotRemoveTheLastEnterpriseAdmin() {
        CurrentSession platform = platformSession();
        ApiException result = assertThrows(ApiException.class, () -> userAdmin.update(platform,
                U_ADMIN_A.toString(), new UpdateUserDTO(null, "disabled", null)));
        assertEquals(409, result.status());
        assertEquals("active", userAdmin.get(platform, U_ADMIN_A.toString()).status());
    }

    @Test
    void removingRolePermissionInvalidatesExistingExecutionReference() throws SQLException {
        CurrentSession admin = switchedSession("adminA", T_A, 1L);
        RoleVO role = roleAdmin.createRole(admin, new CreateRoleDTO(
                "tenant", "ref-auditor", "引用审计角色", null, List.of("tenant:audit:read")));
        tenantAdmin.replaceMemberRoles(admin, M_MEMBER_A.toString(),
                new MemberRolesDTO(List.of("ref-auditor"), 2L));
        var login = sessionService.login(new LoginDTO("memberA", PASSWORD, "workforce", KNOWLEDGE_AUD));
        sessionService.switchTenant(login.accessToken(), new SwitchTenantDTO(T_A.toString(), 1L));
        String runtimeAudience = "langgraph-runtime";
        String runtimeId = "role-ref-runtime";
        String runtimeSecret = "role-ref-secret-0123456789abcdef0123456";
        try (Connection connection = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences) "
                             + "VALUES (?, ?, ?, ARRAY['identity:introspect'], ARRAY['langgraph-runtime'])")) {
            statement.setString(1, runtimeId);
            statement.setString(2, "撤权回归客户端");
            statement.setString(3, OpaqueTokens.digest(runtimeSecret));
            statement.executeUpdate();
        }
        InternalClient runtime = authenticator.authenticate(basic(runtimeId, runtimeSecret));
        JsonNode before = mapper.valueToTree(introspectionService.introspect(runtime,
                new IntrospectDTO(login.accessToken(), null, runtimeAudience, null, true)));
        assertTrue(before.path("active").asBoolean());
        assertTrue(before.path("permissions").toString().contains("tenant:audit:read"));
        JsonNode context = before.path("execution_context");
        var revisions = mapper.treeToValue(context.path("revisions"),
                com.airagent.iam.internal.dto.RevisionsDTO.class);
        var reference = new com.airagent.iam.internal.dto.ExecutionContextRefDTO(
                context.path("verification_ref").asText(), revisions);

        roleAdmin.replacePermissions(admin, role.id(), new RolePermissionsDTO(List.of()));
        JsonNode after = mapper.valueToTree(introspectionService.introspect(runtime,
                new IntrospectDTO(null, reference, runtimeAudience, null, false)));
        assertFalse(after.path("active").asBoolean());
        assertFalse(after.path("context_matches").asBoolean());
    }

    @Test
    void auditLogsArePartitionScoped() {
        CurrentSession platform = platformSession();
        userAdmin.create(platform,
                new CreateUserDTO("audited01", "审计用户", NEW_PASSWORD));

        // B 企业管理员制造一条 B 的审计
        CurrentSession adminB = switchedSession("adminA", T_B, 1L);
        tenantAdmin.createDepartment(adminB, T_B.toString(),
                new CreateDepartmentDTO("BD1", "B部门", null));

        // 平台：可见 tenant_id IS NULL 的平台事件
        PageVO<AuditLogVO> platformLogs =
                auditAdmin.list(platform, new AuditLogQueryDTO(200, null, "admin.user.create"));
        assertTrue(platformLogs.items().stream().anyMatch(l -> l.tenantId() == null));

        // A 企业：只见 A，不见平台 NULL 行也不见 B 行
        CurrentSession adminA = switchedSession("adminA", T_A, 1L);
        tenantAdmin.createDepartment(adminA, T_A.toString(),
                new CreateDepartmentDTO("AD1", "A部门", null));
        PageVO<AuditLogVO> tenantALogs =
                auditAdmin.list(adminA, new AuditLogQueryDTO(200, null, null));
        assertFalse(tenantALogs.items().isEmpty());
        assertTrue(tenantALogs.items().stream()
                .allMatch(l -> T_A.toString().equals(l.tenantId())));
    }

    // ================================================================ 5.4 审计与授权同事务

    @Test
    void auditMapperKeepsJsonPaginationAndBoundParameters() {
        CurrentSession platform = platformSession();
        userAdmin.create(platform, new CreateUserDTO("auditpage01", "分页用户一", NEW_PASSWORD));
        userAdmin.create(platform, new CreateUserDTO("auditpage02", "分页用户二", NEW_PASSWORD));

        PageVO<AuditLogVO> first = auditAdmin.list(platform,
                new AuditLogQueryDTO(1, null, "admin.user.create"));
        assertEquals(1, first.items().size());
        assertNotNull(first.nextCursor());
        assertTrue(first.items().getFirst().detail().isObject());
        assertEquals(U_PLATFORM.toString(), first.items().getFirst().actorUserId());

        PageVO<AuditLogVO> second = auditAdmin.list(platform,
                new AuditLogQueryDTO(1, first.nextCursor(), "admin.user.create"));
        assertEquals(1, second.items().size());
        assertTrue(second.items().getFirst().id() < first.items().getFirst().id());
        assertTrue(auditAdmin.list(platform,
                new AuditLogQueryDTO(20, null, "' OR 1=1 --")).items().isEmpty());

        ApiException invalidCursor = assertThrows(ApiException.class, () -> auditAdmin.list(platform,
                new AuditLogQueryDTO(20, "LTE", null)));
        assertEquals(400, invalidCursor.status());
        assertThrows(ApiException.class, () -> new AuditLogQueryDTO(201, null, null));
    }

    @Test
    void whenAuditCannotBeWrittenAuthorizationChangeRollsBack() throws Exception {
        // 真实 DB 级故障模拟（非 mock）：回收 iam_app 对 write_audit 的 EXECUTE，
        // 建档事务在审计步失败，用户行必须随事务整体回滚。
        try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
             Statement st = con.createStatement()) {
            // 函数默认对 PUBLIC 授予 EXECUTE；必须同时回收 PUBLIC 与 iam_app 才构成真实失败
            st.execute("REVOKE EXECUTE ON FUNCTION iam_auth.write_audit("
                    + "uuid, uuid, text, text, text, text, jsonb, text) FROM PUBLIC, iam_app");
        }
        try {
            // 审计组件把失败包成 IllegalStateException 以强制事务回滚（不经 4xx 吞掉）
            RuntimeException failed = assertThrows(RuntimeException.class, () -> userAdmin.create(
                    platformSession(),
                    new CreateUserDTO("auditfail01", "审计失败回滚", NEW_PASSWORD)));
            assertNotNull(failed.getMessage());
            try (Connection con = DriverManager.getConnection(
                    migrateJdbcUrl, migrateUser, migratePassword);
                 Statement st = con.createStatement();
                 var rs = st.executeQuery(
                         "SELECT count(*) FROM iam.users WHERE account = 'auditfail01'")) {
                rs.next();
                assertEquals(0L, rs.getLong(1), "审计失败时建档必须整体回滚");
            }
        } finally {
            try (Connection con = DriverManager.getConnection(migrateJdbcUrl, migrateUser, migratePassword);
                 Statement st = con.createStatement()) {
                st.execute("GRANT EXECUTE ON FUNCTION iam_auth.write_audit("
                        + "uuid, uuid, text, text, text, text, jsonb, text) TO PUBLIC");
            }
        }
    }

    // ================================================================ 5.5 SA 列表/详情/停用

    @Test
    void serviceAccountListDetailAndImmediateDisable() {
        CurrentSession platform = platformSession();
        ServiceAccountVO sa = serviceAccountService.create(platform,
                new CreateServiceAccountDTO("sa-g5-surface", "第5组服务账号",
                        T_A.toString(), List.of(KNOWLEDGE_AUD), 90, List.of("tenant:member:read")));
        ServiceTokenIssuedVO issued = serviceAccountService.issueToken(platform, sa.id(),
                new CreateServiceTokenDTO(null));

        PageVO<ServiceAccountVO> list = serviceAccountService.list(platform, T_A.toString(), 50, null);
        assertTrue(list.items().stream().anyMatch(v -> v.id().equals(sa.id())));

        ServiceAccountDetailVO detail = serviceAccountService.get(platform, sa.id());
        assertEquals(1, detail.tokens().size());
        assertEquals(issued.credentialId(), detail.tokens().get(0).credentialId());
        // 任何视图/日志载体不得携带原始 secret
        JsonNode tree = mapper.convertValue(detail, JsonNode.class);
        assertFalse(tree.toString().contains(issued.secret()), "详情不得泄漏令牌秘密");
        assertNull(detail.tokens().get(0).revokedAt());

        // 停用即时反映到 introspection（每次主库读取），重新启用后恢复
        com.airagent.iam.internal.dto.IntrospectDTO introspectReq =
                new IntrospectDTO(issued.secret(), null, KNOWLEDGE_AUD, null, null);
        Object active = introspectionService.introspect(
                authenticator.authenticate(basic(KNOWLEDGE_CLIENT, KNOWLEDGE_SECRET)), introspectReq);
        JsonNode activeNode = mapper.convertValue(active, JsonNode.class);
        assertTrue(activeNode.path("active").asBoolean());

        ServiceAccountVO disabled = serviceAccountService.updateStatus(platform, sa.id(),
                new UpdateServiceAccountDTO("disabled"));
        assertEquals("disabled", disabled.status());
        Object afterDisable = introspectionService.introspect(knowledge, introspectReq);
        JsonNode disabledNode = mapper.convertValue(afterDisable, JsonNode.class);
        assertFalse(disabledNode.path("active").asBoolean());

        ServiceAccountVO reEnabled = serviceAccountService.updateStatus(platform, sa.id(),
                new UpdateServiceAccountDTO("active"));
        assertEquals("active", reEnabled.status());
        Object afterEnable = introspectionService.introspect(knowledge, introspectReq);
        assertTrue(mapper.convertValue(afterEnable, JsonNode.class).path("active").asBoolean());
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
        // B 内给管理员角色，用于跨企业写尝试（必须被应用层/RLS 拒绝）
        insertMembershipRole(con, T_B, M_ADMIN_A_IN_B, ROLE_TENANT_ADMIN);
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

    private void seedInternalClient(Connection con) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences) "
                        + "VALUES (?, ?, ?, ?, ?)")) {
            ps.setString(1, KNOWLEDGE_CLIENT);
            ps.setString(2, KNOWLEDGE_CLIENT);
            ps.setString(3, OpaqueTokens.digest(KNOWLEDGE_SECRET));
            ps.setObject(4, con.createArrayOf("text", new String[]{"identity:introspect"}));
            ps.setObject(5, con.createArrayOf("text", new String[]{KNOWLEDGE_AUD}));
            ps.executeUpdate();
        }
    }

    private String login(String account, String password) {
        return sessionService.login(
                new LoginDTO(account, password, "workforce", "iam-admin")).accessToken();
    }

    private String login(String account) {
        return login(account, PASSWORD);
    }

    private CurrentSession platformSession() {
        return sessionService.requireCurrent(login("platformAdmin"));
    }

    private CurrentSession switchedSession(String account, UUID tenant, long expectedCtxVersion) {
        String token = login(account);
        sessionService.switchTenant(token,
                new SwitchTenantDTO(tenant.toString(), expectedCtxVersion));
        return sessionService.requireCurrent(token);
    }

    private String basic(String clientId, String secret) {
        return "Basic " + java.util.Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}
