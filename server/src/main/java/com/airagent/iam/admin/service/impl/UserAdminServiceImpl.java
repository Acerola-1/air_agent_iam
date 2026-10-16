package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.dto.CreateUserDTO;
import com.airagent.iam.admin.dto.PlatformRolesDTO;
import com.airagent.iam.admin.dto.ResetPasswordDTO;
import com.airagent.iam.admin.dto.UpdateUserDTO;
import com.airagent.iam.admin.entity.UserDO;
import com.airagent.iam.admin.mapper.RoleMapper;
import com.airagent.iam.admin.mapper.UserMapper;
import com.airagent.iam.admin.service.UserAdminService;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * {@link UserAdminService} 实现：平台账号管理（权限码 {@code platform:user:*}）。
 *
 * <p>统一编排模式：先按会话权限快照裁决（{@link AdminSupport#requirePermission}），
 * 再经 {@link TransactionTemplate} 开启事务；事务第一步调用
 * {@link AdminSupport#setContext} 写入 PostgreSQL 请求上下文（platform 线为
 * {@code app.is_platform=on}、租户为空），行可见性交由 iam.users 的 RLS 策略裁决。
 * 数据库约束冲突（唯一键等）由 {@link PgErrorTranslator} 翻译为对应 HTTP 语义。
 *
 * <p>关键边界：平台角色的授予/回收推进关联主体授权代次；最后一名有效平台超管的
 * 停用与撤权由数据库触发器（guard_last_admin，23514）兜底拒绝；停用与重置口令
 * 都即时撤销目标全部会话（含其当前会话），Redis 会话键删除经同事务 outbox 投递。
 * 审计写入与业务变更同事务，审计失败整体回滚。
 *
 * @author Acerola
 */
@Service
public class UserAdminServiceImpl implements UserAdminService {

    /** 平台账号读取权限码（列表与详情共用）。 */
    static final String PERM_USER_READ = "platform:user:read";
    /** 平台账号写权限码：创建、显示名与状态变更。 */
    static final String PERM_USER_WRITE = "platform:user:write";
    /** 管理员重置他人口令的独立权限码，与写权限分离。 */
    static final String PERM_PASSWORD_RESET = "platform:user:password:reset";
    /** 平台角色分配权限码。 */
    static final String PERM_ROLE_ASSIGN = "platform:user:role:assign";

    /** 账号与平台角色数据访问。 */
    private final UserMapper userMapper;
    /** 角色权限查询（越界授予校验）。 */
    private final RoleMapper roleMapper;
    /** 编程式事务边界。 */
    private final TransactionTemplate tx;
    /** 权限裁决/上下文/游标/审计共用组件。 */
    private final AdminSupport support;
    /** 口令强度校验与 BCrypt 摘要。 */
    private final PasswordHasher passwordHasher;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param userMapper      账号与平台角色数据访问
     * @param roleMapper      角色权限查询（用于越界授予校验）
     * @param tx              编程式事务边界（本类不使用声明式 @Transactional）
     * @param support         权限裁决、上下文、游标与审计的共用组件
     * @param passwordHasher  口令强度校验与 BCrypt 摘要生成
     */
    public UserAdminServiceImpl(UserMapper userMapper, RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support,
                            PasswordHasher passwordHasher) {
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.tx = tx;
        this.support = support;
        this.passwordHasher = passwordHasher;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：keyset 分页以多取一行（limit+1）探测 {@code hasMore}，
     * 仅当确有下一页且本页非空时才生成 {@code nextCursor}；每行的平台角色码
     * 逐行查询装配（列表行数受 limit 上限约束）。
     */
    @Override
    public PageVO<UserVO> list(CurrentSession actor, Integer limitRaw, String cursorRaw, String q) {
        support.requirePermission(actor, PERM_USER_READ);
        int limit = support.clampLimit(limitRaw);
        String cursor = support.decodeCursor(cursorRaw);
        return tx.execute(status -> {
            support.setContext(actor.userId(), null, true);
            UUID afterId = cursor == null ? null : AdminSupport.parseUuid(cursor, "cursor");
            List<UserDO> rows = userMapper.selectPage(q, afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<UserVO> items = rows.stream().limit(limit).map(this::toView).toList();
            String next = hasMore && !items.isEmpty()
                    ? support.encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：读取前先做 UUID 与权限校验；行经 {@link #loadView} 装配，
     * 不存在或 RLS 不可见统一 404。
     */
    @Override
    public UserVO get(CurrentSession actor, String userId) {
        support.requirePermission(actor, PERM_USER_READ);
        UUID id = AdminSupport.parseUuid(userId, "user_id");
        return tx.execute(status -> {
            support.setContext(actor.userId(), null, true);
            return loadView(id);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：明文口令只在本方法内存在（强度校验后立即替换为 BCrypt 摘要），
     * 任何日志与审计 detail 不落出口令；account 必须匹配可打印 ASCII 3..64。
     * 审计记录 admin.user.create（不含口令），返回体经列裁剪视图装配。
     */
    @Override
    public UserVO create(CurrentSession actor, CreateUserDTO req) {
        support.requirePermission(actor, PERM_USER_WRITE);
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.account() == null || !req.account().matches("\\p{Graph}{3,64}")) {
            throw ApiException.badRequest("account 不合法");
        }
        if (req.displayName() == null || req.displayName().isBlank() || req.displayName().length() > 128) {
            throw ApiException.badRequest("display_name 不合法");
        }
        passwordHasher.validateStrength(req.password());
        String hash = passwordHasher.hash(req.password());
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), null, true);
                UUID id = userMapper.insert(req.account(), req.displayName(), hash);
                support.audit(null, actor.userId(), "admin.user.create", "user", id.toString(),
                        Map.of("account", req.account(), "display_name", req.displayName()));
                return loadView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：以 {@code SELECT ... FOR UPDATE} 行锁串行化同一账号的并发写；
     * 修订基线在锁后读取比对（不一致 409）。两个字段分别条件更新——仅显示名变化
     * 不推进授权代次；status 置 disabled 时触发器推进代次，并撤销目标全部会话、
     * 将 Redis 键删除入 outbox（原因 admin.user_disable）。updated==0 防御
     * 锁后不可见，统一 404。
     */
    @Override
    public UserVO update(CurrentSession actor, String userId, UpdateUserDTO req) {
        support.requirePermission(actor, PERM_USER_WRITE);
        UUID id = AdminSupport.parseUuid(userId, "user_id");
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.status() != null && !req.status().equals("active") && !req.status().equals("disabled")) {
            throw ApiException.badRequest("status 仅支持 active/disabled");
        }
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), null, true);
                UserDO existing = userMapper.selectForUpdate(id);
                if (existing == null) {
                    throw ApiException.notFound("用户不存在");
                }
                long revision = existing.authRevision();
                if (req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("用户修订冲突，请刷新后重试");
                }
                if (req.displayName() != null) {
                    if (req.displayName().isBlank() || req.displayName().length() > 128) {
                        throw ApiException.badRequest("display_name 不合法");
                    }
                    int updated = userMapper.updateDisplayName(id, req.displayName());
                    if (updated == 0) {
                        throw ApiException.notFound("用户不存在");
                    }
                }
                if (req.status() != null) {
                    int updated = userMapper.updateStatus(id, req.status());
                    if (updated == 0) {
                        throw ApiException.notFound("用户不存在");
                    }
                    if ("disabled".equals(req.status())) {
                        revokeSessionsAndEnqueue(actor, id, "admin.user_disable");
                    }
                }
                support.audit(null, actor.userId(), "admin.user.update", "user", id.toString(),
                        Map.of("status", req.status() == null ? "" : req.status(),
                                "display_name_changed", req.displayName() != null));
                return loadView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：事务内先 FOR UPDATE 校验存在与修订基线，再经 SECURITY DEFINER
     * 函数写摘要（触发器因口令变化推进代次），随后 {@code revokeSessions}（p_keep
     * 为空）撤销全部活跃会话并再次推进代次——两步顺序不可颠倒，注释见原实现行内说明。
     * 被撤会话的 Redis 键删除同事务入 outbox；审计 admin.user.password_reset 的
     * detail 为空（不落任何口令信息）。
     */
    @Override
    public void resetPassword(CurrentSession actor, String userId, ResetPasswordDTO req) {
        support.requirePermission(actor, PERM_PASSWORD_RESET);
        UUID id = AdminSupport.parseUuid(userId, "user_id");
        if (req == null || req.newPassword() == null) {
            throw ApiException.badRequest("new_password 必填");
        }
        passwordHasher.validateStrength(req.newPassword());
        String hash = passwordHasher.hash(req.newPassword());
        try {
            tx.executeWithoutResult(status -> {
                support.setContext(actor.userId(), null, true);
                UserDO existing = userMapper.selectForUpdate(id);
                if (existing == null) {
                    throw ApiException.notFound("用户不存在");
                }
                long revision = existing.authRevision();
                if (req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("用户修订冲突，请刷新后重试");
                }
                // 先改密（触发器推进代次），再撤销目标全部会话（再推进代次），Redis 键经 outbox 删除
                userMapper.setPassword(id, hash);
                revokeSessionsAndEnqueue(actor, id, "admin.password_reset");
                support.audit(null, actor.userId(), "admin.user.password_reset", "user", id.toString(),
                        Map.of());
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：delete-then-insert 全量替换在持锁事务内完成，中途失败整体回滚；
     * 越界校验仅对非 platform_super_admin 的 actor 生效（超管可授任意活跃角色）。
     */
    @Override
    public UserVO replacePlatformRoles(CurrentSession actor, String userId, PlatformRolesDTO req) {
        support.requirePermission(actor, PERM_ROLE_ASSIGN);
        UUID id = AdminSupport.parseUuid(userId, "user_id");
        List<String> codes = AdminSupport.sanitizeCodes(req == null ? null : req.roleCodes());
        try {
            return tx.execute(status -> {
                support.setContext(actor.userId(), null, true);
                UserDO existing = userMapper.selectForUpdate(id);
                if (existing == null) {
                    throw ApiException.notFound("用户不存在");
                }
                long revision = existing.authRevision();
                if (req != null && req.expectedRevision() != null && req.expectedRevision() != revision) {
                    throw ApiException.conflict("用户修订冲突，请刷新后重试");
                }
                List<UUID> roleIds = resolvePlatformRoles(actor, codes);
                userMapper.deletePlatformRoles(id);
                for (UUID roleId : roleIds) {
                    userMapper.insertPlatformRole(id, roleId, actor.userId());
                }
                support.audit(null, actor.userId(), "admin.user.platform_roles.replace", "user",
                        id.toString(), Map.of("roles", codes));
                return loadView(id);
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 内部辅助

    /**
     * 撤销目标全部活跃会话并把 Redis 键删除投递到同事务 outbox。
     *
     * @param actor       当前会话（仅上下文用，不参与权限判断）
     * @param targetUser  被撤销会话的用户 UUID
     * @param reason      写入 revoke_reason 列的审计原因码
     */
    private void revokeSessionsAndEnqueue(CurrentSession actor, UUID targetUser, String reason) {
        List<String> digests = userMapper.revokeSessions(targetUser, reason);
        if (!digests.isEmpty()) {
            support.enqueueRedisDeletes(digests);
        }
    }

    /**
     * 将角色码解析为可授予的平台角色 id，并执行越界授予校验。
     *
     * <p>codes 为空直接返回空列表（等价清空）。任一角色非活跃/未知则整体 400；
     * actor 非 platform_super_admin 时，每个角色的权限集合必须是 actor 自身
     * 权限集合的子集，否则 403。
     *
     * @param actor 当前会话快照（提供权限快照）
     * @param codes 已消毒去重的角色码列表
     * @return 与 codes 一一对应的角色 id
     */
    private List<UUID> resolvePlatformRoles(CurrentSession actor, List<String> codes) {
        if (codes.isEmpty()) {
            return List.of();
        }
        List<UUID> roleIds = userMapper.selectPlatformRoleIds(codes);
        if (roleIds.size() != codes.size()) {
            throw ApiException.badRequest("存在未知或停用的平台角色");
        }
        if (!actor.snapshot().hasPlatformRole("platform_super_admin")) {
            for (UUID roleId : roleIds) {
                if (!actor.snapshot().permissions().containsAll(roleMapper.selectPermissionCodes(roleId))) {
                    throw ApiException.forbidden("不能授予超出自身可授范围的角色");
                }
            }
        }
        return roleIds;
    }

    /**
     * 读取并装配账号视图。
     *
     * @param id 用户 UUID
     * @return 账号视图
     * @throws ApiException 404 当行不存在或 RLS 不可见
     */
    private UserVO loadView(UUID id) {
        UserDO user = userMapper.selectById(id);
        if (user == null) {
            throw ApiException.notFound("用户不存在");
        }
        return toView(user);
    }

    /**
     * DO 到 VO 的转换：追加平台角色码，创建时间统一格式化为 UTC ISO-8601 文本。
     *
     * @param user 账号持久化行
     * @return 对外视图（不含口令摘要）
     */
    private UserVO toView(UserDO user) {
        return new UserVO(user.id().toString(), user.realm(), user.account(), user.displayName(),
                user.status(), user.authRevision(), userMapper.selectPlatformRoleCodes(user.id()),
                user.createdAt().withOffsetSameInstant(java.time.ZoneOffset.UTC).toString());
    }
}
