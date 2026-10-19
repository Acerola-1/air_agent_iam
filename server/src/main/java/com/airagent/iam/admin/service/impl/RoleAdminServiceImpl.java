package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.ResourceGrantSupport;
import com.airagent.iam.admin.entity.ResourcePermissionDO;
import com.airagent.iam.admin.dto.CreateRoleDTO;
import com.airagent.iam.admin.dto.RolePermissionsDTO;
import com.airagent.iam.admin.dto.UpdateRoleDTO;
import com.airagent.iam.admin.entity.PermissionDO;
import com.airagent.iam.admin.entity.RoleDO;
import com.airagent.iam.admin.mapper.RoleMapper;
import com.airagent.iam.admin.service.RoleAdminService;
import com.airagent.iam.admin.vo.GrantableTreeVO;
import com.airagent.iam.admin.vo.PermissionStateVO;
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
 * {@link RoleAdminService} 实现：角色建档、局部更新、权限集合替换与权限目录（Service 层）。
 *
 * <p>统一编排模式：先按会话权限快照裁决（{@link AdminSupport#requirePermission}），
 * 再经 {@link TransactionTemplate} 开启事务；事务第一步调用 {@link AdminSupport#setContext}
 * 写入 PostgreSQL 请求上下文，行可见性交由 iam.roles / iam.role_permissions 的 RLS 策略裁决。
 * 数据库约束冲突由 {@link PgErrorTranslator} 翻译为对应 HTTP 语义，审计与业务变更同事务。
 *
 * <p>平台/企业两条授权面严格分离：平台线（{@code platform:role:*}）以平台上下文操作全部角色，
 * 企业线（{@code tenant:role:*}）只能操作内置全局模板与本租户自定义角色，且必须先选择企业上下文。
 * 可授范围也是分层的：企业管理员仅能配置可下放的企业域权限。资源权限需目录启用和本企业开通；
 * 资源管理资格与原写权限组合可完成首次授权，普通权限仍受自身权限子集约束。
 *
 * <p>关键边界：角色与其权限集合的任何变化都由数据库触发器推进引用主体
 * （账号 auth_revision、成员 revision）的授权代次，旧权限快照立即失效，因此本类不需要
 * 显式撤销会话；内置角色一律拒绝修改；角色没有修订列，故本接口不接受乐观并发基线。
 *
 * @author Acerola
 */
@Service
public class RoleAdminServiceImpl implements RoleAdminService {

    /** 平台角色读取权限码：可见全部角色与完整权限目录。 */
    static final String PERM_PLATFORM_ROLE_READ = "platform:role:read";
    /** 平台角色写权限码：创建/修改平台域角色与任意角色的权限集合（平台线）。 */
    static final String PERM_PLATFORM_ROLE_WRITE = "platform:role:write";
    /** 企业角色读取权限码：仅可见内置模板与本租户角色。 */
    static final String PERM_TENANT_ROLE_READ = "tenant:role:read";
    /** 企业角色写权限码：仅能维护本租户自定义角色的企业域权限集合。 */
    static final String PERM_TENANT_ROLE_WRITE = "tenant:role:write";
    /** 企业资源授权管理资格码：可配置已开通可下放的资源权限，不赋予读取能力。 */
    static final String PERM_TENANT_RESOURCE_GRANT = "tenant:resource:grant";

    /** 角色与权限数据访问。 */
    private final RoleMapper roleMapper;
    /** 编程式事务边界。 */
    private final TransactionTemplate tx;
    /** 权限裁决/上下文/审计共用组件。 */
    private final AdminSupport support;
    private final ResourceGrantSupport grants;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param roleMapper 角色与权限目录数据访问
     * @param tx         编程式事务边界（本类不使用声明式 @Transactional）
     * @param support    权限裁决、上下文、游标与审计的共用组件
     */
    public RoleAdminServiceImpl(RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support, ResourceGrantSupport grants) {
        this.roleMapper = roleMapper;
        this.tx = tx;
        this.support = support;
        this.grants = grants;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：显式企业列表与仅有企业读权限的请求始终限定当前企业及全局企业模板；
     * 平台角色列表要求平台读权限。scope 过滤值在校验 lambda 内判定，
     * 因此非法 scope 会在事务内抛 400 并整体回滚（无写入，副作用仅为上下文设置）。
     * 分页以多取一行（limit+1）探测 {@code hasMore}，每行的权限码逐行查询装配。
     */
    @Override
    public PageVO<RoleVO> listRoles(CurrentSession actor, String scopeRaw, Integer limitRaw,
                                    String cursorRaw) {
        boolean platform = actor.snapshot().permissions().contains(PERM_PLATFORM_ROLE_READ);
        boolean tenant = actor.snapshot().permissions().contains(PERM_TENANT_ROLE_READ);
        if (!platform && !tenant) {
            throw ApiException.forbidden("缺少角色查看权限");
        }
        if ("platform".equals(scopeRaw) && !platform) throw ApiException.forbidden("缺少平台角色查看权限");
        boolean tenantView = "tenant".equals(scopeRaw) || !platform;
        UUID listingTenant = tenantView ? support.requireCurrentTenant(actor) : null;
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            if (!tenantView) {
                support.setContext(actor.userId(), null, true);
            } else {
                support.setContext(actor.userId(), support.requireCurrentTenant(actor), false);
            }
            String scope = scopeRaw == null ? null : switch (scopeRaw) {
                case "platform", "tenant" -> scopeRaw;
                default -> throw ApiException.badRequest("scope 仅支持 platform/tenant");
            };
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<RoleDO> rows = roleMapper.selectPage(tenantView ? "tenant" : scope, afterId, limit + 1, listingTenant);
            boolean hasMore = rows.size() > limit;
            List<RoleVO> items = rows.stream().limit(limit).map(row -> toView(actor, row)).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：scope 缺失时不猜测默认值，直接 400；两条授权面各自先判权限再决定租户，
     * 企业角色把租户写死为会话当前企业（客户端无法指定归属）。
     * 角色插入与权限集合写入在同一事务内完成，权限校验不通过则角色不残留；
     * 审计 admin.role.create 落在角色自身租户（平台角色为 {@code null}）。
     */
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
                if (platformScope && grants.permissions(codes).stream().anyMatch(p -> p.resourceCode() != null)) throw ApiException.conflict("平台角色不可携带资源权限");
                grants.lockWrite(actor, tenantId, codes, req.expectedContext(), req.expectedTenantRevision());
                UUID id = roleMapper.insert(req.scope(), tenantId, req.code(), req.name(), req.description());
                replacePermissionRows(actor, id, codes);
                support.audit(tenantId, actor.userId(), "admin.role.create", "role", id.toString(),
                        Map.of("scope", req.scope(), "code", req.code(), "permissions", codes));
                return roleView(actor, id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先经 {@link #loadRoleRow} 设置上下文、按角色自身 scope 裁决权限并确认存在，
     * 内置角色在此之后立即拒绝（403）。SQL 更新走 COALESCE 局部更新，返回值不再检查——
     * 存在性已由同事务的前置读取保证。审计的租户维度取角色自身归属租户。
     */
    @Override
    public RoleVO updateRole(CurrentSession actor, String roleIdRaw, UpdateRoleDTO req) {
        UUID roleId = AdminSupport.parseUuid(roleIdRaw, "role_id");
        if (req != null && req.expectedContext() != null) grants.requireContext(actor, req.expectedContext());
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
            grants.lockWrite(actor, tenantId, roleMapper.selectPermissionCodes(roleId), req.expectedContext(), req.expectedTenantRevision());
            roleMapper.lockById(roleId);
            roleMapper.update(roleId, req.name(), req.description(), req.status());
            support.audit(tenantId, actor.userId(), "admin.role.update", "role", roleId.toString(),
                    Map.of("scope", scope, "status", req.status() == null ? "" : req.status()));
            return roleView(actor, roleId);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：权限码经 {@link AdminSupport#sanitizeCodes} 消毒（{@code null} 载荷等价空集合，
     * 即清空角色权限）；作用域与可授性校验、越界授予校验与 delete-then-insert 全在
     * {@link #replacePermissionRows} 内完成，触发器会使引用主体授权代次前进。
     */
    @Override
    public RoleVO replacePermissions(CurrentSession actor, String roleIdRaw,
                                       RolePermissionsDTO req) {
        UUID roleId = AdminSupport.parseUuid(roleIdRaw, "role_id");
        if (req != null && req.expectedContext() != null) grants.requireContext(actor, req.expectedContext());
        List<String> codes = AdminSupport.sanitizeCodes(req == null ? null : req.permissionCodes());
        return tx.execute(status -> {
            RoleDO role = loadRoleRow(actor, roleId, true);
            UUID tenantId = role.tenantId();
            if (role.builtin()) {
                throw ApiException.forbidden("内置角色不可修改");
            }
            List<String> combined = new ArrayList<>(codes);
            combined.addAll(roleMapper.selectPermissionCodes(roleId));
            grants.lockWrite(actor, tenantId, combined.stream().distinct().toList(),
                    req == null ? null : req.expectedContext(), req == null ? null : req.expectedTenantRevision());
            roleMapper.lockById(roleId);
            replacePermissionRows(actor, roleId, codes);
            support.audit(tenantId, actor.userId(), "admin.role.permissions.replace", "role",
                    roleId.toString(), Map.of("permissions", codes));
            return roleView(actor, roleId);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：读权限二选一决定上下文（平台优先），目录查询已过滤资源型权限；
     * 结果不分页，由控制器包装为 items 数组。
     */
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
     * {@inheritDoc}
     *
     * <p>实现细节：读或写权限任一即可见（授权界面需要写权限但可能无读权限）；
     * 平台上下文优先；平台组仅在有平台面权限时出现，企业组对两条授权面都返回，
     * 叶子再按 actor 自身权限快照裁剪。
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

    // ---------------------------------------------------------------- 内部辅助

    /**
     * 读取指定授权面的可授权限并裁剪为 actor 可用叶子。
     *
     * <p>数据源为 {@link RoleMapper#selectGrantable}（活跃，企业面要求可下放；资源还需目标企业开通）；
     * 非平台超级管理员只会看到自己已持有的码，因此界面无法越权勾选。
     * 调用前必须已设置好事务上下文。
     *
     * @param actor 当前会话快照（提供权限快照与超管身份）
     * @param scope 授权面，仅 {@code platform} / {@code tenant}
     * @param name  分组显示名（界面文案，不参与判定）
     * @return 分组视图；actor 无任何该面可授码时叶子为空列表
     */
    private GrantableTreeVO.Group loadGroup(CurrentSession actor, String scope, String name) {
        boolean isSuper = actor.snapshot().hasPlatformRole("platform_super_admin");
        boolean hasGrantMgmt = actor.snapshot().permissions().contains(PERM_TENANT_RESOURCE_GRANT);
        UUID currentTenant = actor.currentTenantId();
        List<GrantableTreeVO.Leaf> leaves = roleMapper.selectGrantable(scope).stream()
                .filter(permission -> {
                    if (permission.resourceCode() != null) {
                        // 资源码仅在已开通且可下放时进入可授树
                        if (!hasGrantMgmt && !actor.snapshot().permissions().contains(permission.code())) {
                            return false;
                        }
                        if (currentTenant == null) return false;
                        return isResourceEntitled(currentTenant, permission.resourceCode());
                    }
                    if (isSuper) return true;
                    return actor.snapshot().permissions().contains(permission.code());
                })
                .map(permission -> new GrantableTreeVO.Leaf(permission.code(), permission.nameZh(),
                        permission.resourceCode(),
                        permission.resourceCode() == null ? null
                                : grants.resourceNameZh(permission.resourceCode()))).toList();
        return new GrantableTreeVO.Group(scope, name, leaves);
    }

    private boolean isResourceEntitled(UUID tenantId, String resourceCode) {
        return roleMapper.countActiveEntitlement(tenantId, resourceCode) > 0;
    }

    /**
     * 载入角色行，按角色自身 scope 裁决操作者权限与租户归属，并副作用地设置事务上下文。
     *
     * <p>上下文设置发生在读取之前：具备该面（读或写）权限时走平台上下文，否则走企业上下文，
     * 因此本方法只能在事务内调用。企业角色若归属他企业则 403；
     * 内置企业模板（归属为空）允许读取，但写路径仍受 RLS 与业务裁决约束。
     *
     * @param actor  当前会话快照
     * @param roleId 角色 UUID
     * @param write  {@code true} 表示写路径（改用 {@code *:role:write} 判定），{@code false} 表示读路径
     * @return 角色行（已处于匹配的上下文下）
     * @throws ApiException 403 缺对应面权限、或角色属他企业；404 角色不存在或 RLS 不可见；
     *                      400 企业路径下 actor 未选择企业上下文
     */
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

    /**
     * 把角色的权限集合全量替换为给定码集合，并逐层校验可授范围。
     *
     * <p>三道校验有固定先后：未知权限码 400（按码解析的命中数与入参不等）；
     * 权限不在该角色可授范围 409（平台角色/全局模板资源码拒绝，企业独有角色按开通和管理资格裁决）；
     * 越出 actor 自身权限集合 403（平台超级管理员豁免）。删除与批量插入连续执行，
     * 中途失败由事务整体回滚；数据库触发器 role_permissions_boundary 是同规则的最后一道兜底。
     * 空集合是合法的“清空”语义，此时不会调用按码查询与批量插入（避免生成非法 SQL）。
     *
     * @param actor  当前会话快照（提供权限快照与 granted_by 审计列取值）
     * @param roleId 角色 UUID，须已由调用方确认存在且可写
     * @param codes  已消毒去重的权限码列表；空列表表示清空该角色权限
     * @throws ApiException 400 存在未知权限码；403 越界授予；409 权限不在该角色可授范围
     *                      （批量插入触发的约束违例同样经 {@link PgErrorTranslator} 归入 409）
     */
    private void replacePermissionRows(CurrentSession actor, UUID roleId, List<String> codes) {
        List<String> original = roleMapper.selectPermissionCodes(roleId);
        List<String> added = codes.stream().filter(c -> !original.contains(c)).toList();
        RoleDO role = roleMapper.selectById(roleId);
        for (ResourcePermissionDO p : grants.permissions(added)) {
            if ("tenant".equals(role.scope())) {
                if (p.resourceCode() != null && role.tenantId() == null) {
                    throw ApiException.conflict("全局模板不可携带资源权限");
                }
                grants.requireGrantable(actor, role.tenantId(), p);
            } else {
                if (p.resourceCode() != null) throw ApiException.conflict("平台角色不可携带资源权限");
                if (!"active".equals(p.status())) throw ApiException.conflict("权限已停用");
                if (!actor.snapshot().hasPlatformRole("platform_super_admin")
                        && !actor.snapshot().permissions().contains(p.code())) {
                    throw ApiException.forbidden("不能授予超出自身可授范围的权限");
                }
            }
        }
        for (String code : original) if (!codes.contains(code)) roleMapper.deletePermission(roleId, code);
        if (!added.isEmpty()) roleMapper.insertPermissions(roleId, actor.userId(), roleMapper.selectPermissionsByCodes(added));
    }

    /**
     * 读取并装配角色视图（含其权限码列表）。
     *
     * @param id 角色 UUID
     * @return 角色视图
     * @throws ApiException 404 当行不存在或当前上下文 RLS 不可见
     */
    private RoleVO roleView(CurrentSession actor, UUID id) {
        RoleDO role = roleMapper.selectById(id);
        if (role == null) {
            throw ApiException.notFound("角色不存在");
        }
        return toView(actor, role);
    }

    /**
     * DO 到 VO 的转换：UUID 统一转字符串文本，额外查询该角色的权限码。
     *
     * @param role 角色持久化行
     * @return 对外视图（权限码按 code 升序，无权限时为空列表）
     */
    private RoleVO toView(CurrentSession actor, RoleDO role) {
        List<String> codes = roleMapper.selectPermissionCodes(role.id());
        List<PermissionStateVO> states = new ArrayList<>();
        UUID tenant = role.tenantId();
        for (ResourcePermissionDO p : grants.permissions(codes)) {
            String reason = !"active".equals(role.status()) ? "role_disabled"
                    : !"active".equals(p.status()) ? "permission_disabled" : null;
            if (reason == null && p.resourceCode() != null) {
                reason = grants.resourceInvalidReason(tenant, p);
            }
            boolean grantable = reason == null && (p.resourceCode() == null
                    ? actor.snapshot().hasPlatformRole("platform_super_admin") || actor.snapshot().permissions().contains(p.code())
                    : p.grantableToTenants() && (actor.snapshot().permissions().contains("tenant:resource:grant")
                            || actor.snapshot().permissions().contains(p.code())));
            states.add(new PermissionStateVO(p.code(), true, reason == null, grantable, reason));
        }
        return new RoleVO(role.id().toString(), role.code(), role.scope(),
                tenant == null ? null : tenant.toString(), role.name(), role.description(),
                role.builtin(), role.status(), codes, states);
    }
}
