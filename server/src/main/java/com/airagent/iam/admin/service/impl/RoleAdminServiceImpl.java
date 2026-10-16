package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.dto.CreateRoleDTO;
import com.airagent.iam.admin.dto.RolePermissionsDTO;
import com.airagent.iam.admin.dto.UpdateRoleDTO;
import com.airagent.iam.admin.entity.PermissionDO;
import com.airagent.iam.admin.entity.RoleDO;
import com.airagent.iam.admin.mapper.RoleMapper;
import com.airagent.iam.admin.service.RoleAdminService;
import com.airagent.iam.admin.vo.GrantableTreeVO;
import com.airagent.iam.admin.vo.PermissionVO;
import com.airagent.iam.admin.vo.RoleVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 自定义角色、权限目录与可授权限树。
 *
 * <p>平台/企业可授分离：企业管理员只见 grant_scope=tenant 且 grantable_to_tenants 的非资源权限；
 * 资源型权限（resource_code 非空）在 I1a 前不出现在可授树中，DB 触发器同时硬拒。
 */
@Service
public class RoleAdminServiceImpl implements RoleAdminService {

    static final String PERM_PLATFORM_ROLE_READ = "platform:role:read";
    static final String PERM_PLATFORM_ROLE_WRITE = "platform:role:write";
    static final String PERM_TENANT_ROLE_READ = "tenant:role:read";
    static final String PERM_TENANT_ROLE_WRITE = "tenant:role:write";

    private final RoleMapper roleMapper;
    private final TransactionTemplate tx;
    private final AdminSupport support;

    public RoleAdminServiceImpl(RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support) {
        this.roleMapper = roleMapper;
        this.tx = tx;
        this.support = support;
    }

    @Override
    public PageVO<RoleVO> listRoles(CurrentSession actor, String scopeRaw, Integer limitRaw,
                                    String cursorRaw) {
        boolean platform = actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_READ);
        boolean tenant = actor.snapshot().permissions().contains(PERM_TENANT_ROLE_READ);
        if (!platform && !tenant) {
            throw ApiException.forbidden("缺少角色查看权限");
        }
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            if (platform) {
                support.setContext(actor.userId(), null, true);
            } else {
                support.setContext(actor.userId(), support.requireCurrentTenant(actor), false);
            }
            String scope = scopeRaw == null ? null : switch (scopeRaw) {
                case "platform", "tenant" -> scopeRaw;
                default -> throw ApiException.badRequest("scope 仅支持 platform/tenant");
            };
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<RoleDO> rows = roleMapper.selectPage(scope, afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<RoleVO> items = rows.stream().limit(limit).map(this::toView).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    @Override
    public RoleVO createRole(CurrentSession actor, CreateRoleDTO req) {
        if (req == null || req.code() == null || !req.code().matches("[a-z][a-z0-9_-]{2,63}")) {
            throw ApiException.badRequest("code 需为 3-64 位小写字母数字/_-");
        }
        if (req.name() == null || req.name().isBlank() || req.name().length() > 128) {
            throw ApiException.badRequest("name 不合法");
        }
        List<String> codes = AdminSupport.sanitizeCodes(req.permissionCodes());
        boolean platformScope = "platform".equals(req.scope());
        boolean tenantScope = "tenant".equals(req.scope());
        if (!platformScope && !tenantScope) {
            throw ApiException.badRequest("scope 必填且仅支持 platform/tenant");
        }
        boolean canPlatform = actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_WRITE);
        boolean canTenant = actor.snapshot().permissions().contains(PERM_TENANT_ROLE_WRITE);
        if (platformScope && !canPlatform) {
            throw ApiException.forbidden("无平台角色写权限");
        }
        final UUID tenantId;
        if (tenantScope) {
            if (!canTenant) {
                throw ApiException.forbidden("无企业角色写权限");
            }
            tenantId = support.requireCurrentTenant(actor);
        } else {
            tenantId = null;
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, platformScope);
                UUID id = roleMapper.insert(req.scope(), tenantId, req.code(), req.name(), req.description());
                replacePermissionRows(actor, id, codes);
                support.audit(tenantId, actor.userId(), "admin.role.create", "role", id.toString(),
                        Map.of("scope", req.scope(), "code", req.code(), "permissions", codes));
                return roleView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    @Override
    public RoleVO updateRole(CurrentSession actor, String roleIdRaw, UpdateRoleDTO req) {
        UUID roleId = AdminSupport.parseUuid(roleIdRaw, "role_id");
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.status() != null && !req.status().equals("active") && !req.status().equals("disabled")) {
            throw ApiException.badRequest("status 仅支持 active/disabled");
        }
        return tx.execute(status -> {
            RoleDO role = loadRoleRow(actor, roleId, true);
            String scope = role.scope();
            UUID tenantId = role.tenantId();
            if (role.builtin()) {
                throw ApiException.forbidden("内置角色不可修改");
            }
            if (req.name() != null && (req.name().isBlank() || req.name().length() > 128)) {
                throw ApiException.badRequest("name 不合法");
            }
            roleMapper.update(roleId, req.name(), req.description(), req.status());
            support.audit(tenantId, actor.userId(), "admin.role.update", "role", roleId.toString(),
                    Map.of("scope", scope, "status", req.status() == null ? "" : req.status()));
            return roleView(roleId);
        });
    }

    @Override
    public RoleVO replacePermissions(CurrentSession actor, String roleIdRaw,
                                       RolePermissionsDTO req) {
        UUID roleId = AdminSupport.parseUuid(roleIdRaw, "role_id");
        List<String> codes = AdminSupport.sanitizeCodes(req == null ? null : req.permissionCodes());
        return tx.execute(status -> {
            RoleDO role = loadRoleRow(actor, roleId, true);
            UUID tenantId = role.tenantId();
            if (role.builtin()) {
                throw ApiException.forbidden("内置角色不可修改");
            }
            replacePermissionRows(actor, roleId, codes);
            support.audit(tenantId, actor.userId(), "admin.role.permissions.replace", "role",
                    roleId.toString(), Map.of("permissions", codes));
            return roleView(roleId);
        });
    }

    /** 权限目录：平台看全部；企业主体不返回平台专属权限。 */
    @Override
    public List<PermissionVO> listPermissions(CurrentSession actor) {
        boolean platform = actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_READ);
        boolean tenant = actor.snapshot().permissions().contains(PERM_TENANT_ROLE_READ);
        if (!platform && !tenant) {
            throw ApiException.forbidden("缺少权限目录查看权限");
        }
        return tx.execute(status -> {
            if (platform) {
                support.setContext(actor.userId(), null, true);
            } else {
                support.setContext(actor.userId(), support.requireCurrentTenant(actor), false);
            }
            // I1：资源型权限（resource_code 非空）走 I1a entitlement，不进可授权限目录/可授树
            return roleMapper.selectCatalog(platform).stream()
                    .map(row -> new PermissionVO(row.code(), row.nameZh(), row.scope(), row.resourceCode()))
                    .toList();
        });
    }

    /**
     * 当前主体可授权限树：仅含可分配到角色的非资源权限；
     * 企业主体不出现平台组，资源型权限在 I1a 前整组缺席。
     */
    @Override
    public GrantableTreeVO grantableTree(CurrentSession actor) {
        boolean platform = actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_READ)
                || actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_WRITE);
        boolean tenant = actor.snapshot().permissions().contains(PERM_TENANT_ROLE_READ)
                || actor.snapshot().permissions().contains(PERM_TENANT_ROLE_WRITE);
        if (!platform && !tenant) {
            throw ApiException.forbidden("缺少可授权限查看权限");
        }
        return tx.execute(status -> {
            if (platform) {
                support.setContext(actor.userId(), null, true);
            } else {
                support.setContext(actor.userId(), support.requireCurrentTenant(actor), false);
            }
            List<GrantableTreeVO.Group> groups = new ArrayList<>();
            if (platform) {
                groups.add(loadGroup(actor, "platform", "平台权限"));
            }
            if (tenant || platform) {
                groups.add(loadGroup(actor, "tenant", "企业权限"));
            }
            return new GrantableTreeVO(groups);
        });
    }

    // ---------------------------------------------------------------- 辅助

    private GrantableTreeVO.Group loadGroup(CurrentSession actor, String scope, String name) {
        List<GrantableTreeVO.Leaf> leaves = roleMapper.selectGrantable(scope).stream()
                .filter(permission -> actor.snapshot().hasPlatformRole("platform_super_admin")
                        || actor.snapshot().permissions().contains(permission.code()))
                .map(permission -> new GrantableTreeVO.Leaf(permission.code(), permission.nameZh(),
                        permission.resourceCode())).toList();
        return new GrantableTreeVO.Group(scope, name, leaves);
    }

    /** 载入角色行并按 scope 做操作者权限/租户匹配，同时设置事务上下文。 */
    private RoleDO loadRoleRow(CurrentSession actor, UUID roleId, boolean write) {
        boolean canPlatform = actor.snapshot().permissions().contains(
                write ? PERM_PLATFORM_ROLE_WRITE : PERM_PLATFORM_ROLE_READ);
        boolean canTenant = actor.snapshot().permissions().contains(
                write ? PERM_TENANT_ROLE_WRITE : PERM_TENANT_ROLE_READ);
        RoleDO role;
        if (canPlatform) {
            support.setContext(actor.userId(), null, true);
        } else {
            support.setContext(actor.userId(), support.requireCurrentTenant(actor), false);
        }
        role = roleMapper.selectById(roleId);
        if (role == null) {
            throw ApiException.notFound("角色不存在");
        }
        String scope = role.scope();
        UUID roleTenant = role.tenantId();
        if ("platform".equals(scope)) {
            if (!canPlatform) {
                throw ApiException.forbidden("无权操作平台角色");
            }
        } else if ("tenant".equals(scope)) {
            if (!canTenant) {
                throw ApiException.forbidden("无权操作企业角色");
            }
            UUID current = support.requireCurrentTenant(actor);
            if (roleTenant != null && !roleTenant.equals(current)) {
                throw ApiException.forbidden("角色不属于当前企业");
            }
        }
        return role;
    }

    /** 角色权限必须在操作者自身可授集合内；数据库同时约束权限域。 */
    private void replacePermissionRows(CurrentSession actor, UUID roleId, List<String> codes) {
        List<PermissionDO> permissions = codes.isEmpty() ? List.of() : roleMapper.selectPermissionsByCodes(codes);
        if (permissions.size() != codes.size()) {
            throw ApiException.badRequest("存在未知权限码");
        }
        RoleDO role = roleMapper.selectById(roleId);
        if (permissions.stream().anyMatch(permission -> permission.resourceCode() != null
                || ("tenant".equals(role.scope()) && !permission.grantableToTenants()))) {
            throw ApiException.conflict("权限不在该角色的可授范围内");
        }
        if (!actor.snapshot().hasPlatformRole("platform_super_admin")
                && !actor.snapshot().permissions().containsAll(codes)) {
            throw ApiException.forbidden("不能授予超出自身可授范围的权限");
        }
        roleMapper.deletePermissions(roleId);
        if (!permissions.isEmpty()) {
            try {
                roleMapper.insertPermissions(roleId, actor.userId(), permissions);
            } catch (org.springframework.dao.DataAccessException ex) {
                throw PgErrorTranslator.toApiException(ex);
            }
        }
    }

    private RoleVO roleView(UUID id) {
        RoleDO role = roleMapper.selectById(id);
        if (role == null) {
            throw ApiException.notFound("角色不存在");
        }
        return toView(role);
    }

    private RoleVO toView(RoleDO role) {
        return new RoleVO(role.id().toString(), role.code(), role.scope(),
                role.tenantId() == null ? null : role.tenantId().toString(), role.name(),
                role.description(), role.builtin(), role.status(), roleMapper.selectPermissionCodes(role.id()));
    }
}
