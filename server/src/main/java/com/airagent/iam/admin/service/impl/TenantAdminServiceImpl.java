package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.dto.CreateDepartmentDTO;
import com.airagent.iam.admin.dto.CreateMembershipDTO;
import com.airagent.iam.admin.dto.CreateTenantDTO;
import com.airagent.iam.admin.dto.MemberRolesDTO;
import com.airagent.iam.admin.dto.UpdateDepartmentDTO;
import com.airagent.iam.admin.dto.UpdateMembershipDTO;
import com.airagent.iam.admin.dto.UpdateTenantDTO;
import com.airagent.iam.admin.entity.DepartmentDO;
import com.airagent.iam.admin.entity.MembershipDO;
import com.airagent.iam.admin.entity.TenantDO;
import com.airagent.iam.admin.entity.UserDO;
import com.airagent.iam.admin.mapper.RoleMapper;
import com.airagent.iam.admin.mapper.TenantMapper;
import com.airagent.iam.admin.mapper.UserMapper;
import com.airagent.iam.admin.service.TenantAdminService;
import com.airagent.iam.admin.vo.DepartmentVO;
import com.airagent.iam.admin.vo.MemberVO;
import com.airagent.iam.admin.vo.TenantVO;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 企业建档/状态与企业内成员、部门管理。
 *
 * <p>租户作用域以会话 currentTenantId 为准（不接受请求体自报租户）；同租户复合 FK、无环、
 * 最后管理员与角色边界全部由数据库触发器兜底，应用层先做明确 4xx 翻译。
 */
@Service
public class TenantAdminServiceImpl implements TenantAdminService {

    static final String PERM_TENANT_READ = "platform:tenant:read";
    static final String PERM_TENANT_WRITE = "platform:tenant:write";
    static final String PERM_MEMBER_READ = "tenant:member:read";
    static final String PERM_MEMBER_WRITE = "tenant:member:write";
    static final String PERM_DEPT_READ = "tenant:department:read";
    static final String PERM_DEPT_WRITE = "tenant:department:write";
    static final String PERM_ROLE_WRITE = "tenant:role:write";

    private final TenantMapper tenantMapper;
    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final TransactionTemplate tx;
    private final AdminSupport support;
    private final PasswordHasher passwordHasher;

    public TenantAdminServiceImpl(TenantMapper tenantMapper, UserMapper userMapper, RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support,
                              PasswordHasher passwordHasher) {
        this.tenantMapper = tenantMapper;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.tx = tx;
        this.support = support;
        this.passwordHasher = passwordHasher;
    }

    // ---------------------------------------------------------------- 企业

    @Override
    public PageVO<TenantVO> listTenants(CurrentSession actor, Integer limitRaw, String cursorRaw) {
        support.requirePermission(actor, PERM_TENANT_READ);
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            support.setContext(actor.userId(), null, true);
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<TenantDO> rows = tenantMapper.selectTenants(afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<TenantVO> items = rows.stream().limit(limit).map(this::toTenantView).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    @Override
    public TenantVO getTenant(CurrentSession actor, String tenantIdRaw) {
        UUID id = AdminSupport.parseUuid(tenantIdRaw, "tenant_id");
        boolean platformRead = actor.snapshot().permissions().contains(PERM_TENANT_READ);
        boolean tenantRead = actor.snapshot().permissions().contains(PERM_MEMBER_READ)
                || actor.snapshot().permissions().contains(PERM_DEPT_READ);
        if (!platformRead && !tenantRead) {
            throw ApiException.forbidden("缺少企业查看权限");
        }
        if (!platformRead) {
            if (actor.currentTenantId() == null) {
                throw ApiException.badRequest("请先选择企业上下文");
            }
            if (!id.equals(actor.currentTenantId())) {
                throw ApiException.forbidden("只能查看当前企业上下文内的资源");
            }
        }
        return tx.execute(status -> {
            support.setContext(actor.userId(), platformRead ? null : id, platformRead);
            return tenantView(id);
        });
    }

    @Override
    public TenantVO createTenant(CurrentSession actor, CreateTenantDTO req) {
        support.requirePermission(actor, PERM_TENANT_WRITE);
        if (req == null || req.code() == null || !req.code().matches("[A-Za-z0-9][A-Za-z0-9_-]{1,63}")) {
            throw ApiException.badRequest("code 需为 2-64 位字母数字/_-");
        }
        if (req.name() == null || req.name().isBlank() || req.name().length() > 128) {
            throw ApiException.badRequest("name 不合法");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), null, true);
                UUID id = tenantMapper.insertTenant(req.code(), req.name(), actor.userId());
                UUID initialAdmin = req.initialAdminUserId() == null ? actor.userId()
                        : AdminSupport.parseUuid(req.initialAdminUserId(), "initial_admin_user_id");
                if (!initialAdmin.equals(actor.userId())) {
                    support.requirePermission(actor, "platform:user:read");
                }
                UserDO initialUser = userMapper.selectById(initialAdmin);
                if (initialUser == null || !"active".equals(initialUser.status())) {
                    throw ApiException.badRequest("首位管理员必须是启用的现有账号");
                }
                support.setContext(actor.userId(), id, false);
                UUID membershipId = tenantMapper.insertMembership(id, initialAdmin, null, actor.userId());
                List<UUID> roles = tenantMapper.selectTenantRoleIds(id, List.of("tenant_admin"));
                if (roles.size() != 1) {
                    throw new IllegalStateException("首位企业管理员角色配置异常");
                }
                tenantMapper.insertMemberRole(id, membershipId, roles.getFirst(), actor.userId());
                support.audit(id, actor.userId(), "admin.tenant.bootstrap", "tenant_membership",
                        membershipId.toString(), Map.of("user_id", initialAdmin.toString()));
                support.setContext(actor.userId(), null, true);
                support.audit(null, actor.userId(), "admin.tenant.create", "tenant", id.toString(),
                        Map.of("code", req.code(), "name", req.name()));
                return tenantView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public TenantVO updateTenant(CurrentSession actor, String tenantId, UpdateTenantDTO req) {
        support.requirePermission(actor, PERM_TENANT_WRITE);
        UUID id = AdminSupport.parseUuid(tenantId, "tenant_id");
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.status() != null && !req.status().equals("active") && !req.status().equals("suspended")) {
            throw ApiException.badRequest("status 仅支持 active/suspended");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), null, true);
                TenantDO existing = tenantMapper.lockTenant(id);
                if (existing == null) {
                    throw ApiException.notFound("企业不存在");
                }
                long revision = existing.authRevision();
                if (req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("企业修订冲突，请刷新后重试");
                }
                if (req.name() != null) {
                    if (req.name().isBlank() || req.name().length() > 128) {
                        throw ApiException.badRequest("name 不合法");
                    }

                }
                tenantMapper.updateTenant(id, req.name(), req.status());
                support.audit(id, actor.userId(), "admin.tenant.update", "tenant", id.toString(),
                        Map.of("status", req.status() == null ? "" : req.status(),
                                "name_changed", req.name() != null));
                return tenantView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 成员

    @Override
    public PageVO<MemberVO> listMembers(CurrentSession actor, String tenantIdRaw, Integer limitRaw,
                                        String cursorRaw) {
        support.requirePermission(actor, PERM_MEMBER_READ);
        UUID tenantId = resolveScopedTenant(actor, tenantIdRaw);
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            support.setContext(actor.userId(), tenantId, false);
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<MembershipDO> rows = tenantMapper.selectMembers(tenantId, afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<MemberVO> items = rows.stream().limit(limit).map(row -> toMemberView(row)).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    @Override
    public MemberVO createMembership(CurrentSession actor, CreateMembershipDTO req) {
        support.requirePermission(actor, PERM_MEMBER_WRITE);
        UUID tenantId = resolveScopedTenant(actor, req == null ? null : req.tenantId());
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        List<String> roleCodes = AdminSupport.sanitizeCodes(req.roleCodes());
        try {
            return tx.execute(status -> {
                UUID userId;
                // users 是全局表：WITH CHECK 仅允许平台上下文插入；显式建档/查重都在平台上下文完成，
                // 绝不依据同名账号隐式合并。审计仍记 target tenant，授权判定不依赖该标志。
                support.setContext(actor.userId(), null, true);
                if (req.userId() != null) {
                    userId = AdminSupport.parseUuid(req.userId(), "user_id");
                    support.setContext(actor.userId(), tenantId, false);
                    if (tenantMapper.countMembership(tenantId, userId) > 0) {
                        throw ApiException.conflict("该用户已是此企业成员");
                    }
                    support.requirePermission(actor, "platform:user:read");
                    support.setContext(actor.userId(), null, true);
                    if (userMapper.selectById(userId) == null) {
                        throw ApiException.badRequest("指定用户不存在，禁止隐式建档");
                    }
                } else {
                    if (req.account() == null || !req.account().matches("\\p{Graph}{3,64}")) {
                        throw ApiException.badRequest("account 不合法（未提供 user_id 时必须显式建档）");
                    }
                    // 先查重：已存在账号一律 409，要求显式 user_id，绝不按同名自动合并
                    List<UUID> existing = tenantMapper.findUserIds(req.account());
                    if (!existing.isEmpty()) {
                        throw ApiException.conflict(
                                "账号已存在；关联既有成员必须显式传 user_id，禁止按同名自动合并");
                    }
                    if (req.displayName() == null || req.displayName().isBlank()
                            || req.displayName().length() > 128) {
                        throw ApiException.badRequest("display_name 不合法");
                    }
                    passwordHasher.validateStrength(req.password());
                    userId = userMapper.insert(req.account(), req.displayName(), passwordHasher.hash(req.password()));
                    support.audit(tenantId, actor.userId(), "admin.user.create", "user",
                            userId.toString(), Map.of("account", req.account(),
                                    "display_name", req.displayName(), "via", "membership"));
                }
                // 回到企业上下文：成员、部门、角色全部按本租户 RLS/复合 FK/触发器裁决
                support.setContext(actor.userId(), tenantId, false);
                UUID departmentId = resolveDepartment(tenantId, req.departmentId());
                UUID membershipId = tenantMapper.insertMembership(tenantId, userId, departmentId, actor.userId());
                List<UUID> roleIds = resolveTenantRoles(actor, tenantId, roleCodes);
                for (UUID roleId : roleIds) {
                    tenantMapper.insertMemberRole(tenantId, membershipId, roleId, actor.userId());
                }
                support.audit(tenantId, actor.userId(), "admin.membership.create", "tenant_membership",
                        membershipId.toString(), Map.of(
                                "user_id", userId.toString(), "roles", roleCodes));
                return memberView(tenantId, membershipId);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            // 同企业重复成员（memberships_tenant_user_uk 23505，可能被包成 DuplicateKey）
            org.postgresql.util.PSQLException psql = PgErrorTranslator.deepest(e);
            if (psql != null && "23505".equals(psql.getSQLState())
                    && e.getMessage() != null && e.getMessage().contains("tenant_memberships")) {
                throw ApiException.conflict("该用户已是此企业成员");
            }
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public MemberVO updateMembership(CurrentSession actor, String membershipIdRaw,
                                       UpdateMembershipDTO req) {
        support.requirePermission(actor, PERM_MEMBER_WRITE);
        UUID tenantId = actor.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        UUID membershipId = AdminSupport.parseUuid(membershipIdRaw, "membership_id");
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.status() != null && !req.status().equals("active") && !req.status().equals("disabled")) {
            throw ApiException.badRequest("status 仅支持 active/disabled");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                MembershipDO existing = tenantMapper.lockMembership(tenantId, membershipId);
                if (existing == null) {
                    throw ApiException.notFound("成员不存在或不属于当前企业");
                }
                long revision = existing.revision();
                if (req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("成员修订冲突，请刷新后重试");
                }
                UUID departmentId = resolveDepartment(tenantId, req.departmentId());
                int updated = tenantMapper.updateMembership(tenantId, membershipId, departmentId, req.status());
                if (updated == 0) {
                    throw ApiException.notFound("成员不存在");
                }
                support.audit(tenantId, actor.userId(), "admin.membership.update", "tenant_membership",
                        membershipId.toString(), Map.of("status", req.status() == null ? "" : req.status(),
                                "department_changed", req.departmentId() != null));
                return memberView(tenantId, membershipId);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public void deleteMembership(CurrentSession actor, String membershipIdRaw) {
        support.requirePermission(actor, PERM_MEMBER_WRITE);
        UUID tenantId = actor.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        UUID membershipId = AdminSupport.parseUuid(membershipIdRaw, "membership_id");
        try {
            tx.executeWithoutResult(status -> {
                support.setContext(actor.userId(), tenantId, false);
                int deleted = tenantMapper.deleteMembership(tenantId, membershipId);
                if (deleted == 0) {
                    throw ApiException.notFound("成员不存在或不属于当前企业");
                }
                support.audit(tenantId, actor.userId(), "admin.membership.delete", "tenant_membership",
                        membershipId.toString(), Map.of());
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public MemberVO replaceMemberRoles(CurrentSession actor, String membershipIdRaw,
                                         MemberRolesDTO req) {
        support.requirePermission(actor, PERM_ROLE_WRITE);
        UUID tenantId = actor.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        UUID membershipId = AdminSupport.parseUuid(membershipIdRaw, "membership_id");
        List<String> codes = AdminSupport.sanitizeCodes(req == null ? null : req.roleCodes());
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                MembershipDO existing = tenantMapper.lockMembership(tenantId, membershipId);
                if (existing == null) {
                    throw ApiException.notFound("成员不存在或不属于当前企业");
                }
                long revision = existing.revision();
                if (req != null && req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("成员修订冲突，请刷新后重试");
                }
                List<UUID> roleIds = resolveTenantRoles(actor, tenantId, codes);
                tenantMapper.deleteMemberRoles(tenantId, membershipId);
                for (UUID roleId : roleIds) {
                    tenantMapper.insertMemberRole(tenantId, membershipId, roleId, actor.userId());
                }
                support.audit(tenantId, actor.userId(), "admin.membership.roles.replace",
                        "tenant_membership", membershipId.toString(), Map.of("roles", codes));
                return memberView(tenantId, membershipId);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 部门

    @Override
    public PageVO<DepartmentVO> listDepartments(CurrentSession actor, String tenantIdRaw,
                                                Integer limitRaw, String cursorRaw) {
        support.requirePermission(actor, PERM_DEPT_READ);
        UUID tenantId = resolveScopedTenant(actor, tenantIdRaw);
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            support.setContext(actor.userId(), tenantId, false);
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<DepartmentDO> rows = tenantMapper.selectDepartments(tenantId, afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<DepartmentVO> items = rows.stream().limit(limit).map(this::toDepartmentView).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    @Override
    public DepartmentVO createDepartment(CurrentSession actor, String tenantIdRaw,
                                           CreateDepartmentDTO req) {
        support.requirePermission(actor, PERM_DEPT_WRITE);
        UUID tenantId = resolveScopedTenant(actor, tenantIdRaw);
        if (req != null) {
            checkDeclaredContext(actor, req.tenantId(), req.expectedCtxVersion());
        }
        if (req == null || req.code() == null || !req.code().matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) {
            throw ApiException.badRequest("code 需为 1-64 位字母数字/_-");
        }
        if (req.name() == null || req.name().isBlank() || req.name().length() > 128) {
            throw ApiException.badRequest("name 不合法");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                UUID parentId = resolveDepartment(tenantId, req.parentId());
                UUID id = tenantMapper.insertDepartment(tenantId, parentId, req.code(), req.name());
                support.audit(tenantId, actor.userId(), "admin.department.create", "department",
                        id.toString(), Map.of("code", req.code(), "name", req.name()));
                return departmentView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public DepartmentVO updateDepartment(CurrentSession actor, String departmentIdRaw,
                                           UpdateDepartmentDTO req) {
        support.requirePermission(actor, PERM_DEPT_WRITE);
        UUID tenantId = actor.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        UUID departmentId = AdminSupport.parseUuid(departmentIdRaw, "department_id");
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        checkDeclaredContext(actor, req.tenantId(), req.expectedCtxVersion());
        if (req.status() != null && !req.status().equals("active") && !req.status().equals("disabled")) {
            throw ApiException.badRequest("status 仅支持 active/disabled");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                UUID parentId = req.parentId() == null ? null : resolveDepartment(tenantId, req.parentId());
                int updated = tenantMapper.updateDepartment(tenantId, departmentId, req.name(),
                        req.parentId() != null, parentId, req.status());
                if (updated == 0) {
                    throw ApiException.notFound("部门不存在或不属于当前企业");
                }
                support.audit(tenantId, actor.userId(), "admin.department.update", "department",
                        departmentId.toString(), Map.of("status", req.status() == null ? "" : req.status()));
                return departmentView(departmentId);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 辅助

    private void checkDeclaredContext(CurrentSession actor, String tenantId, Long expectedVersion) {
        if ((tenantId != null && !tenantId.equals(String.valueOf(actor.currentTenantId())))
                || (expectedVersion != null && expectedVersion != actor.ctxVersion())) {
            throw ApiException.contextChanged("表单企业上下文已变化，请刷新后重试");
        }
    }

    /** 企业域写操作只认会话当前企业；query/body 缺省时用当前企业，跨企业显式拒绝。 */
    private UUID resolveScopedTenant(CurrentSession actor, String requested) {
        UUID current = actor.currentTenantId();
        if (current == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        if (requested != null && !requested.isBlank()) {
            UUID asked = AdminSupport.parseUuid(requested, "tenant_id");
            if (!asked.equals(current)) {
                throw ApiException.forbidden("只能管理当前企业上下文内的资源");
            }
        }
        return current;
    }

    private UUID resolveDepartment(UUID tenantId, String departmentIdRaw) {
        if (departmentIdRaw == null || departmentIdRaw.isBlank()) {
            return null;
        }
        UUID departmentId = AdminSupport.parseUuid(departmentIdRaw, "department_id");
        DepartmentDO department = tenantMapper.selectDepartment(departmentId);
        if (department == null || !tenantId.equals(department.tenantId())) {
            throw ApiException.badRequest("部门不存在或不属于该企业");
        }
        return departmentId;
    }

    /** 企业角色：内置全局模板（tenant_id IS NULL）或本企业自定义角色；平台角色一律拒绝。 */
    private List<UUID> resolveTenantRoles(CurrentSession actor, UUID tenantId, List<String> codes) {
        if (codes.isEmpty()) {
            return List.of();
        }
        support.requirePermission(actor, PERM_ROLE_WRITE);
        List<UUID> roles = tenantMapper.selectTenantRoleIds(tenantId, codes);
        if (roles.size() != codes.size()) {
            throw ApiException.badRequest("存在未知、停用、平台专属或他企业角色");
        }
        for (UUID roleId : roles) {
            if (!actor.snapshot().permissions().containsAll(roleMapper.selectPermissionCodes(roleId))) {
                throw ApiException.forbidden("不能授予超出自身可授范围的角色");
            }
        }
        return roles;
    }

    private TenantVO tenantView(UUID id) {
        TenantDO tenant = tenantMapper.selectTenant(id);
        if (tenant == null) {
            throw ApiException.notFound("企业不存在");
        }
        return toTenantView(tenant);
    }

    private TenantVO toTenantView(TenantDO tenant) {
        return new TenantVO(tenant.id().toString(), tenant.code(), tenant.name(), tenant.status(),
                tenant.authRevision(), tenant.createdAt().withOffsetSameInstant(ZoneOffset.UTC).toString());
    }

    private DepartmentVO departmentView(UUID id) {
        DepartmentDO department = tenantMapper.selectDepartment(id);
        if (department == null) {
            throw ApiException.notFound("部门不存在");
        }
        return toDepartmentView(department);
    }

    private DepartmentVO toDepartmentView(DepartmentDO department) {
        return new DepartmentVO(department.id().toString(), department.tenantId().toString(),
                department.parentId() == null ? null : department.parentId().toString(),
                department.code(), department.name(), department.status());
    }

    private MemberVO memberView(UUID tenantId, UUID membershipId) {
        MembershipDO member = tenantMapper.selectMembership(tenantId, membershipId);
        if (member == null) {
            throw ApiException.notFound("成员不存在");
        }
        return toMemberView(member);
    }

    private MemberVO toMemberView(MembershipDO member) {
        UserDO user = tenantMapper.selectMemberUser(member.id());
        if (user == null) {
            throw ApiException.notFound("成员账号不存在");
        }
        UserVO view = new UserVO(user.id().toString(), user.realm(), user.account(), user.displayName(),
                user.status(), user.authRevision(), List.of(),
                user.createdAt().withOffsetSameInstant(ZoneOffset.UTC).toString());
        return new MemberVO(member.id().toString(), member.tenantId().toString(), view,
                member.departmentId() == null ? null : member.departmentId().toString(), member.status(),
                member.revision(), tenantMapper.selectMemberRoleCodes(member.id()));
    }
}
