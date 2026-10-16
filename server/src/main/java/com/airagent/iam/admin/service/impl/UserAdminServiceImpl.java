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
 * 平台账号管理（platform:user:*）。
 * 平台角色分配受最后有效超管触发器保护；停用/重置密码即时撤销目标全部会话并经 outbox 清 Redis。
 */
@Service
public class UserAdminServiceImpl implements UserAdminService {

    static final String PERM_USER_READ = "platform:user:read";
    static final String PERM_USER_WRITE = "platform:user:write";
    static final String PERM_PASSWORD_RESET = "platform:user:password:reset";
    static final String PERM_ROLE_ASSIGN = "platform:user:role:assign";

    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final TransactionTemplate tx;
    private final AdminSupport support;
    private final PasswordHasher passwordHasher;

    public UserAdminServiceImpl(UserMapper userMapper, RoleMapper roleMapper, TransactionTemplate tx, AdminSupport support,
                            PasswordHasher passwordHasher) {
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.tx = tx;
        this.support = support;
        this.passwordHasher = passwordHasher;
    }

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

    @Override
    public UserVO get(CurrentSession actor, String userId) {
        support.requirePermission(actor, PERM_USER_READ);
        UUID id = AdminSupport.parseUuid(userId, "user_id");
        return tx.execute(status -> {
            support.setContext(actor.userId(), null, true);
            return loadView(id);
        });
    }

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

    private void revokeSessionsAndEnqueue(CurrentSession actor, UUID targetUser, String reason) {
        List<String> digests = userMapper.revokeSessions(targetUser, reason);
        if (!digests.isEmpty()) {
            support.enqueueRedisDeletes(digests);
        }
    }

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

    private UserVO loadView(UUID id) {
        UserDO user = userMapper.selectById(id);
        if (user == null) {
            throw ApiException.notFound("用户不存在");
        }
        return toView(user);
    }

    private UserVO toView(UserDO user) {
        return new UserVO(user.id().toString(), user.realm(), user.account(), user.displayName(),
                user.status(), user.authRevision(), userMapper.selectPlatformRoleCodes(user.id()),
                user.createdAt().withOffsetSameInstant(java.time.ZoneOffset.UTC).toString());
    }
}
