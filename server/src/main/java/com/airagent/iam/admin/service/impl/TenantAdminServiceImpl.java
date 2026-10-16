package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.ResourceGrantSupport;
import com.airagent.iam.admin.dto.ExpectedContextDTO;
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
 * {@link TenantAdminService} 实现：企业建档与状态、企业内成员与部门（Service 层）。
 *
 * <p>统一编排模式：先按会话权限快照裁决（{@link AdminSupport#requirePermission}），再经
 * {@link TransactionTemplate} 开启事务；事务第一步调用 {@link AdminSupport#setContext}
 * 写入 PostgreSQL 请求上下文。同一个方法内部可能多次切换上下文——企业主体行走平台线，
 * 成员/部门/角色行走企业线，账号写入只能发生在平台上下文，审计写入同样受 audit_logs 的
 * RLS 管辖（平台线审计必须回到平台上下文、企业线审计带本租户 id）。
 *
 * <p>租户隔离以会话 currentTenantId 为唯一权威：请求参数或请求体里的 tenant_id 只能缺省或
 * 与当前企业一致（跨企业 403、未选企业 400），部门写接口再叠加
 * {@code expected_ctx_version} 上下文守卫（不一致 409 context_changed）。
 * 同租户复合外键、部门层级无环、最后管理员保护、角色域边界与可授范围全部由数据库触发器兜底，
 * 应用层先做明确的 4xx 翻译；约束违例经 {@link PgErrorTranslator} 映射。
 *
 * <p>关键边界：企业状态与成员状态的变更、成员角色的增删都会由触发器推进对应修订号，
 * 使携带旧基线的会话在权威核验时被拒；停用/移除最后一名有效企业管理员会撞
 * guard_last_admin（409）。业务变更与审计同事务，审计失败整体回滚。
 *
 * @author Acerola
 */
@Service
public class TenantAdminServiceImpl implements TenantAdminService {

    /** 企业读取权限码（平台授权面，可见全部企业）。 */
    static final String PERM_TENANT_READ = "platform:tenant:read";
    /** 企业建档与状态变更权限码（平台授权面）。 */
    static final String PERM_TENANT_WRITE = "platform:tenant:write";
    /** 企业成员读取权限码（企业授权面，需已选择企业）。 */
    static final String PERM_MEMBER_READ = "tenant:member:read";
    /** 企业成员写权限码：新增、部门挂靠、启停与移除。 */
    static final String PERM_MEMBER_WRITE = "tenant:member:write";
    /** 企业部门读取权限码。 */
    static final String PERM_DEPT_READ = "tenant:department:read";
    /** 企业部门写权限码。 */
    static final String PERM_DEPT_WRITE = "tenant:department:write";
    /** 企业角色写权限码：本类仅用于给成员授予/替换角色时的越界校验。 */
    static final String PERM_ROLE_WRITE = "tenant:role:write";

    /** 企业数据访问。 */
    private final TenantMapper tenantMapper;
    /** 账号数据访问（新企业首位管理员）。 */
    private final UserMapper userMapper;
    /** 角色与权限数据访问。 */
    private final RoleMapper roleMapper;
    private final ResourceGrantSupport grants;
    /** 编程式事务边界。 */
    private final TransactionTemplate tx;
    /** 权限裁决/上下文/游标/审计共用组件。 */
    private final AdminSupport support;
    /** 口令强度校验与 BCrypt 摘要。 */
    private final PasswordHasher passwordHasher;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param tenantMapper    企业、成员与部门数据访问
     * @param userMapper      平台账号数据访问（关联既有账号与显式建档）
     * @param roleMapper      角色权限查询（用于越界授予校验）
     * @param tx              编程式事务边界（本类不使用声明式 @Transactional）
     * @param support         权限裁决、上下文、游标与审计的共用组件
     * @param passwordHasher  口令强度校验与 BCrypt 摘要生成
     */
    public TenantAdminServiceImpl(TenantMapper tenantMapper, UserMapper userMapper, RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support,
                              PasswordHasher passwordHasher, ResourceGrantSupport grants) {
        this.tenantMapper = tenantMapper;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.grants = grants;
        this.tx = tx;
        this.support = support;
        this.passwordHasher = passwordHasher;
    }

    // ---------------------------------------------------------------- 企业

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：以平台上下文查询，故不受单一企业 RLS 约束；keyset 分页多取一行探测
     * {@code hasMore}，仅当确有下一页且本页非空时才生成 {@code nextCursor}。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：权限面二选一而非单一码——平台读权限直接按平台上下文读取；
     * 只有企业成员或部门读权限时改用企业上下文，并强制目标企业等于会话当前企业，
     * 使企业管理员可查看自身企业档案却读不到别的企业。UUID 解析在权限判定之前，
     * 因此格式错误的请求不暴露会话权限信息。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：企业行、成员行、内置管理员角色与两条审计在同一事务内顺序完成，
     * 上下文依次为“平台（建企业、校验首位管理员）→ 新企业（写成员与角色、企业内审计）→
     * 平台（平台线审计与出参装配）”。指定他人时额外要求 {@code platform:user:read}，
     * 且目标账号必须存在且状态为 active——账号可见性依赖平台上下文，切企业前必须先读。
     * 内置 {@code tenant_admin} 模板若解析不到恰好一个角色 id，说明种子数据异常，
     * 以内部错误中断（不是调用方可修的 4xx）。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：以 {@code SELECT ... FOR UPDATE} 锁定企业行后再比对修订基线（不一致 409），
     * name 的二次校验发生在持锁之后；更新语句用 COALESCE 做局部更新，
     * 返回值不检查（存在性已由加锁读取保证）。仅状态实际变化会由触发器推进企业授权代次，
     * 令该企业下的活跃会话在权威核验时被拒；企业状态变更不参与最后管理员保护
     * （该保护只覆盖账号状态与授权关系行），并发防护完全依赖行锁与修订比对。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：企业归属经 {@link #resolveScopedTenant} 归一为会话当前企业后写入上下文，
     * 成员行按 id 升序 keyset 分页。每行的账号摘要与角色码走两次关联查询
     * （见 {@link #toMemberView}），行数受 limit 上限约束。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：上下文三段式——平台上下文用于查重与建档、企业上下文用于查重成员与写关系、
     * 再回到企业上下文装配视图。给 {@code userId} 时禁止隐式建档（查不到账号即 400），
     * 并额外要求 {@code platform:user:read}；给 {@code account} 时同名账号一律 409，
     * 要求调用方显式关联，口令只在此处生成 BCrypt 摘要（新账号会多一条
     * admin.user.create 审计，detail 标注 via=membership 且不含口令）。
     * 角色集合经 {@link #resolveTenantRoles} 裁决后与成员插入同事务写入。
     * 唯一键违例若命中 {@code tenant_memberships}，按“已是成员”给出 409 而非通用冲突。
     */
    @Override
    public MemberVO createMembership(CurrentSession actor, CreateMembershipDTO req) {
        support.requirePermission(actor, PERM_MEMBER_WRITE);
        if (req != null && req.expectedContext() != null) grants.requireContext(actor, req.expectedContext());
        UUID tenantId = resolveScopedTenant(actor, req == null ? null : req.tenantId());
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        List<String> roleCodes = AdminSupport.sanitizeCodes(req.roleCodes());
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                List<UUID> roleIds = resolveTenantRoles(actor, tenantId, roleCodes, List.of(), req.expectedContext(), req.expectedTenantRevision());
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：企业归属直接取会话 currentTenantId（本方法不接受请求体租户），
     * 成员行加锁后比对 revision（不一致 409）。部门走 {@link #resolveDepartment} 的全量赋值语义：
     * 请求未带部门即把挂靠清空，因此只想改状态必须回传当前部门。
     * 更新返回 0 行时按 404 处理（防御锁后不可见）。状态变化推进 revision；
     * 停用最后一名有效企业管理员由数据库触发器以 23514 拒绝，经翻译为 409。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：直接按“会话当前企业 + 成员 id”复合条件删除，0 行统一 404
     * （不区分不存在与跨企业，避免泄露存在性）；删除不加行锁、不做修订比对。
     * 该成员的角色关联随复合外键级联清除；若移除的是最后一名有效企业管理员，
     * 触发器以 23514 拒绝并整体回滚，审计不写。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先锁成员行做修订比对，再 delete-then-insert 全量替换；
     * 中途失败整体回滚。角色解析走 {@link #resolveTenantRoles}——只接受企业域角色，
     * 且对平台超级管理员也不豁免越界校验；清空（空集合）等价删除全部关联，
     * 若因此撤掉最后一名有效管理员会撞 409。每次增删都会由触发器推进成员 revision。
     */
    @Override
    public MemberVO replaceMemberRoles(CurrentSession actor, String membershipIdRaw,
                                         MemberRolesDTO req) {
        support.requirePermission(actor, PERM_ROLE_WRITE);
        support.requirePermission(actor, PERM_MEMBER_WRITE);
        if (req != null && req.expectedContext() != null) grants.requireContext(actor, req.expectedContext());
        UUID tenantId = actor.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        UUID membershipId = AdminSupport.parseUuid(membershipIdRaw, "membership_id");
        List<String> codes = AdminSupport.sanitizeCodes(req == null ? null : req.roleCodes());
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), tenantId, false);
                if (tenantMapper.selectMembership(tenantId, membershipId) == null) throw ApiException.notFound("成员不存在或不属于当前企业");
                List<UUID> roleIds = resolveTenantRoles(actor, tenantId, codes,
                        tenantMapper.selectMemberRoleCodes(membershipId),
                        req == null ? null : req.expectedContext(), req == null ? null : req.expectedTenantRevision());
                MembershipDO existing = tenantMapper.lockMembership(tenantId, membershipId);
                if (existing == null) {
                    throw ApiException.notFound("成员不存在或不属于当前企业");
                }
                long revision = existing.revision();
                if (req != null && req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("成员修订冲突，请刷新后重试");
                }
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：企业归属经 {@link #resolveScopedTenant} 归一后写入上下文与 SQL 过滤条件；
     * 返回扁平列表（无 parent 名称解析、无子树聚合），层级由调用方按 parent_id 还原。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：上下文守卫由控制器与服务层双重裁决——控制器要求
     * tenant_id 与 expected_ctx_version 必填（缺失 400），服务层的
     * {@link #checkDeclaredContext} 只在字段出现时比对（请求体缺失时跳过，随后按 code 校验 400）。
     * 上级部门必须已存在且属于本租户，否则 400；同企业编码唯一，冲突经翻译为 409；
     * 层级约束由数据库触发器兜底。部门无修订列，故不存在行级乐观并发检查。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：企业归属取会话 currentTenantId，更新语句按“租户 + 部门 id”复合限定，
     * 0 行即 404。{@code parentId} 只有非空才参与替换（replaceParent 开关），
     * 因此本接口无法把部门降级为顶级；成环由数据库触发器以 23514 拒绝（翻译为 409）。
     * 无行锁、无修订比对，守卫完全依赖上下文版本一致性与数据库约束。
     */
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

    /**
     * 比对请求体自报的表单上下文与会话真实上下文。
     *
     * <p>用于部门写接口：客户端在切企业后仍用旧表单提交时，必须失败而不是写进另一个企业。
     * 两个组件都是“出现才比对”——缺失项由控制器判定为必填（400），服务层保持宽松。
     * 比对目标分别是会话当前企业 id 的文本形式与 {@code auth_sessions.ctx_version}
     * （切换企业时 +1），不匹配一律 409 且 code 为 context_changed（区别于唯一键式的 conflict）。
     *
     * @param actor           当前会话快照
     * @param tenantId        请求体声明的企业 UUID 文本；{@code null} 表示不比对该项
     * @param expectedVersion 请求体声明的会话上下文版本；{@code null} 表示不比对该项
     * @throws ApiException 409 上下文已变化（企业或版本任一不符）
     */
    private void checkDeclaredContext(CurrentSession actor, String tenantId, Long expectedVersion) {
        if ((tenantId != null && !tenantId.equals(String.valueOf(actor.currentTenantId())))
                || (expectedVersion != null && expectedVersion != actor.ctxVersion())) {
            throw ApiException.contextChanged("表单企业上下文已变化，请刷新后重试");
        }
    }

    /**
     * 把可选的企业参数归一为会话当前企业。
     *
     * <p>企业域写操作只认会话当前企业：参数缺省时用当前企业，出现时必须等于当前企业，
     * 因此不存在“用平台权限直接写别租户行”的路径（RLS 同时是最后一道兜底）。
     *
     * @param actor     当前会话快照
     * @param requested 请求参数或请求体中的企业 UUID 文本；{@code null}/空白表示用会话当前企业
     * @return 已确认与一致的租户 UUID
     * @throws ApiException 400 actor 未选择企业上下文或文本非 UUID；403 请求的企业与当前上下文不一致
     */
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

    /**
     * 解析并校验部门挂靠目标。
     *
     * <p>空值语义：{@code null} 或空白返回 {@code null}，即“不挂靠”（在成员更新中还会意味着
     * 清空原挂靠）。非空时必须能在当前上下文读到，且行的租户必须等于入参租户——
     * “不存在”与“跨企业”合并为同一 400，不回显差异。依赖调用方已设置企业上下文。
     *
     * @param tenantId         期望所属的企业 UUID
     * @param departmentIdRaw  部门 UUID 文本；{@code null}/空白表示无挂靠
     * @return 校验通过的部门 UUID，或 {@code null}
     * @throws ApiException 400 文本非 UUID、部门不存在或不属于该企业
     */
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

    /**
     * 将角色码解析为可授予成员的企业角色 id，并执行越界授予校验。
     *
     * <p>codes 为空直接返回空列表（等价清空，且不额外要求角色写权限）。解析口径为
     * {@code scope='tenant'} 且活跃、归属为空（内置全局模板）或等于本租户，
     * 故平台角色、他企业角色与停用角色都命中不了——数量不等即 400。
     * 与企业线的其它校验一致，这里没有平台超级管理员豁免：普通权限必须落在自身权限子集；新增资源许可还可由
     * tenant:resource:grant管理资格授权，但必须满足企业开通。既有失效配置可保留、不可搬运。因 createMembership 入口只判成员写权限，
     * 带角色时必须在此补判 {@code tenant:role:write}。
     *
     * @param actor    当前会话快照（提供权限快照）
     * @param tenantId 目标企业 UUID，取会话当前企业
     * @param codes    已消毒去重的角色码列表
     * @return 与 codes 一一对应的角色 id
     * @throws ApiException 403 缺企业角色写权限或越界授予；400 存在未知、停用、平台专属或他企业角色
     */
    private List<UUID> resolveTenantRoles(CurrentSession actor, UUID tenantId, List<String> codes,
                                          List<String> previous, ExpectedContextDTO expected, Long tenantRevision) {
        if (!codes.isEmpty()) support.requirePermission(actor, PERM_ROLE_WRITE);
        List<UUID> roles = codes.isEmpty() ? List.of() : tenantMapper.selectTenantRoleIds(tenantId, codes);
        if (roles.size() != codes.size()) throw ApiException.badRequest("存在未知、停用或他企业角色");
        List<UUID> original = previous.isEmpty() ? List.of() : tenantMapper.selectTenantRoleIds(tenantId, previous);
        java.util.Set<String> all = new java.util.LinkedHashSet<>();
        for (UUID id : java.util.stream.Stream.concat(roles.stream(), original.stream()).distinct().toList()) all.addAll(roleMapper.selectPermissionCodes(id));
        grants.lockWrite(actor, tenantId, List.copyOf(all), expected, tenantRevision);
        for (UUID id : roles.stream().sorted().toList()) {
            roleMapper.lockById(id);
            for (var permission : grants.permissions(roleMapper.selectPermissionCodes(id))) {
                if (permission.resourceCode() != null && original.contains(id)) continue;
                grants.requireGrantable(actor, tenantId, permission);
            }
        }
        return roles;
    }

    /**
     * 读取并装配企业视图。
     *
     * @param id 企业 UUID
     * @return 企业视图
     * @throws ApiException 404 当行不存在或当前上下文 RLS 不可见
     */
    private TenantVO tenantView(UUID id) {
        TenantDO tenant = tenantMapper.selectTenant(id);
        if (tenant == null) {
            throw ApiException.notFound("企业不存在");
        }
        return toTenantView(tenant);
    }

    /**
     * DO 到 VO 的转换：UUID 转文本，创建时间统一格式化为 UTC ISO-8601 文本。
     *
     * @param tenant 企业持久化行
     * @return 对外视图（不含建档人等内部列）
     */
    private TenantVO toTenantView(TenantDO tenant) {
        return new TenantVO(tenant.id().toString(), tenant.code(), tenant.name(), tenant.status(),
                tenant.authRevision(), tenant.createdAt().withOffsetSameInstant(ZoneOffset.UTC).toString());
    }

    /**
     * 读取并装配部门视图（单个部门，不含子树）。
     *
     * @param id 部门 UUID
     * @return 部门视图
     * @throws ApiException 404 当行不存在或当前上下文 RLS 不可见
     */
    private DepartmentVO departmentView(UUID id) {
        DepartmentDO department = tenantMapper.selectDepartment(id);
        if (department == null) {
            throw ApiException.notFound("部门不存在");
        }
        return toDepartmentView(department);
    }

    /**
     * DO 到 VO 的转换：两个 UUID 组件为 {@code null} 时保持 {@code null}（顶级部门无父）。
     *
     * @param department 部门持久化行
     * @return 对外视图
     */
    private DepartmentVO toDepartmentView(DepartmentDO department) {
        return new DepartmentVO(department.id().toString(), department.tenantId().toString(),
                department.parentId() == null ? null : department.parentId().toString(),
                department.code(), department.name(), department.status());
    }

    /**
     * 读取并装配成员视图，按“租户 + 成员 id”复合限定。
     *
     * @param tenantId     当前企业 UUID（已由上下文与请求一致性校验）
     * @param membershipId 成员关系 UUID
     * @return 成员视图
     * @throws ApiException 404 当成员不存在或不属于该企业
     */
    private MemberVO memberView(UUID tenantId, UUID membershipId) {
        MembershipDO member = tenantMapper.selectMembership(tenantId, membershipId);
        if (member == null) {
            throw ApiException.notFound("成员不存在");
        }
        return toMemberView(member);
    }

    /**
     * DO 到 VO 的装配：账号摘要经 SECURITY DEFINER 函数读取，角色码另行查询。
     *
     * <p>用函数而不是直读 iam.users，是为了让停用的成员也能被展示——账号行在纯企业上下文下
     * 因“同企业活跃成员”分支失效而不可见。账号行缺失（数据不一致）按 404 处理。
     * 内嵌的用户视图刻意把平台角色置为空列表：成员视图只表达租户内授权，
     * 平台角色属于另一条授权面，不在此暴露。
     *
     * @param member 成员关系持久化行
     * @return 成员视图（含账号摘要、部门、状态、修订号与角色码）
     * @throws ApiException 404 当成员对应的账号行不存在
     */
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
