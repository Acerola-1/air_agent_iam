package com.airagent.iam.auth.service.impl;

import cn.dev33.satoken.exception.NotLoginException;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.stp.parameter.SaLoginParameter;
import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.IdentityAssembler;
import com.airagent.iam.auth.dto.ChangePasswordDTO;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.dto.RenewDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.entity.LoginUserDO;
import com.airagent.iam.auth.entity.SessionTimerDO;
import com.airagent.iam.auth.mapper.SessionMapper;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.vo.SessionTimersVO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.satoken.DigestStpLogic;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * 会话权威用例：登录/退出/全退/身份/企业列表/切企业 CAS/续期/改密。
 *
 * <p>每个受保护请求：先验证 Sa-Token Redis 会话存在（依赖失败=503），再读 PG 主库快照
 * （状态/四修订/权限，无跨请求正向授权缓存）。状态变更、审计与 Redis 清理 outbox 同事务。
 */
@Service
public class SessionServiceImpl implements SessionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionServiceImpl.class);
    private static final Set<String> AUDIENCES = Set.of("air-agent", "knowledge", "iam-admin");

    private final SessionMapper sessionMapper;
    private final RequestContextMapper requestContextMapper;
    private final AdminEventMapper eventMapper;
    private final TransactionTemplate tx;
    private final PasswordHasher passwordHasher;
    private final IdentityAssembler assembler;
    private final IamProperties props;
    private final ObjectMapper mapper;
    private final com.airagent.iam.security.internal.RateLimiter rateLimiter;

    public SessionServiceImpl(SessionMapper sessionMapper, RequestContextMapper requestContextMapper,
                              AdminEventMapper eventMapper, TransactionTemplate tx, PasswordHasher passwordHasher,
                          IdentityAssembler assembler, IamProperties props, ObjectMapper mapper,
                          com.airagent.iam.security.internal.RateLimiter rateLimiter) {
        this.sessionMapper = sessionMapper;
        this.requestContextMapper = requestContextMapper;
        this.eventMapper = eventMapper;
        this.tx = tx;
        this.passwordHasher = passwordHasher;
        this.assembler = assembler;
        this.props = props;
        this.mapper = mapper;
        this.rateLimiter = rateLimiter;
    }

    // ---------------------------------------------------------------- 登录

    @Override
    public LoginVO login(LoginDTO req) {
        validateLogin(req);
        // 按 realm+account 固定窗口限流（Redis 故障失败关闭 503），在 bcrypt 之前生效
        rateLimiter.check(com.airagent.iam.security.internal.RateLimiter.SCOPE_LOGIN,
                req.realm() + ":" + req.account());
        LoginUserDO user = sessionMapper.findLogin(req.realm(), req.account());
        boolean passwordOk = user != null && "active".equals(user.status())
                && passwordHasher.matches(req.password(), user.passwordHash());
        if (!passwordOk) {
            // 同一消息避免账号枚举；不记录账号以外任何输入
            throw ApiException.unauthenticated("账号或口令错误");
        }

        UUID userId = user.id();
        String rawToken = OpaqueTokens.newRawToken();
        long absolute = props.session().absoluteTimeoutSeconds();
        long idle = props.session().idleTimeoutSeconds();

        // 先建 Redis Sa-Token 会话；PG 失败时补偿删除，绝不返回未可靠建立的会话。
        SaLoginParameter parameter = new SaLoginParameter()
                .setToken(rawToken)
                .setTimeout(absolute)
                .setIsWriteHeader(false)
                .setIsConcurrent(true)
                .setIsShare(false);
        StpUtil.getStpLogic().createLoginSession(userId.toString(), parameter);

        UUID sessionId;
        try {
            sessionId = tx.execute(status -> {
                setContext(userId, null);
                UUID id = sessionMapper.createSession(userId, req.realm(), req.audience(),
                        OpaqueTokens.digest(rawToken), idle, absolute);
                audit(null, userId, "auth.login", "auth_session", id.toString(),
                        Map.of("audience", req.audience(), "realm", req.realm()));
                return id;
            });
        } catch (RuntimeException ex) {
            try {
                StpUtil.getStpLogic().logoutByTokenValue(rawToken);
            } catch (RuntimeException cleanup) {
                LOGGER.warn("登录失败后 Redis 补偿删除失败 sessionId 未知 requestId={}",
                        org.slf4j.MDC.get("request_id"));
            }
            throw ex;
        }

        AuthoritySnapshot snapshot = requireSnapshot(rawToken);
        if (!sessionId.equals(snapshot.sessionId())) {
            throw ApiException.dependencyUnavailable("会话建立校验失败");
        }
        IdentityVO identity = assembler.toIdentity(snapshot, props.issuer());
        return new LoginVO(rawToken, "Bearer", idle, identity);
    }

    /**
     * SSO 服务端兑换成功后为同一人类签发独立应用会话（受众绑定注册客户端）。
     * 复制中央会话当前企业与 ctx_version；令牌原始值只在本次服务端响应中出现一次。
     */
    @Override
    public LoginVO issueSsoSession(CurrentSession source, String audience) {
        if (!"workforce".equals(source.realm())) {
            throw ApiException.forbidden("仅人类会话可经 SSO 兑换应用会话");
        }
        String rawToken = OpaqueTokens.newRawToken();
        long absolute = props.session().absoluteTimeoutSeconds();
        long idle = props.session().idleTimeoutSeconds();

        SaLoginParameter parameter = new SaLoginParameter()
                .setToken(rawToken)
                .setTimeout(absolute)
                .setIsWriteHeader(false)
                .setIsConcurrent(true)
                .setIsShare(false);
        StpUtil.getStpLogic().createLoginSession(source.userId().toString(), parameter);

        try {
            tx.executeWithoutResult(status -> {
                setContext(source.userId(), source.currentTenantId());
                UUID sessionId = sessionMapper.mintSsoSession(source.sessionId(), audience,
                        OpaqueTokens.digest(rawToken), idle, absolute);
                audit(source.currentTenantId(), source.userId(), "auth.sso_exchange",
                        "auth_session", sessionId.toString(),
                        Map.of("source_session_id", source.sessionId().toString(),
                                "audience", audience));
            });
        } catch (RuntimeException ex) {
            try {
                StpUtil.getStpLogic().logoutByTokenValue(rawToken);
            } catch (RuntimeException cleanup) {
                LOGGER.warn("SSO 兑换失败后 Redis 补偿删除失败 requestId={}",
                        org.slf4j.MDC.get("request_id"));
            }
            throw ex;
        }
        AuthoritySnapshot snapshot = requireSnapshot(rawToken);
        IdentityVO identity = assembler.toIdentity(snapshot, props.issuer());
        return new LoginVO(rawToken, "Bearer", idle, identity);
    }

    // ---------------------------------------------------------------- 退出

    @Override
    public void logout(String rawToken) {
        CurrentSession current;
        try {
            current = requireCurrent(rawToken);
        } catch (ApiException ex) {
            if (ex.status() == 401) {
                return;
            }
            throw ex;
        }
        logout(current);
    }

    @Override
    public void logout(CurrentSession current) {
        tx.executeWithoutResult(status -> {
            setContext(current.userId(), current.currentTenantId());
            String digest = sessionMapper.revokeSession(current.sessionId(), "user.logout");
            if (digest != null) {
                enqueueRedisDelete(List.of(redisKey(digest)));
            }
            audit(current.currentTenantId(), current.userId(), "auth.logout",
                    "auth_session", current.sessionId().toString(), Map.of());
        });
        bestEffortRedisDeleteBySession(current.sessionId());
    }

    @Override
    public void logoutAll(String rawToken) {
        logoutAll(requireCurrent(rawToken));
    }

    @Override
    public void logoutAll(CurrentSession current) {
        tx.executeWithoutResult(status -> {
            setContext(current.userId(), null);
            List<String> digests = sessionMapper.revokeUserSessions(current.userId(), "user.logout_all");
            if (!digests.isEmpty()) {
                enqueueRedisDelete(digests.stream().map(this::redisKey).toList());
            }
            audit(null, current.userId(), "auth.logout_all", "user",
                    current.userId().toString(), Map.of("revoked_sessions", digests.size()));
        });
        bestEffortRedisDeleteBySession(current.sessionId());
    }

    // ---------------------------------------------------------------- 身份

    @Override
    public IdentityVO me(String rawToken) {
        return assembler.toIdentity(requireSnapshot(rawToken), props.issuer());
    }

    @Override
    public IdentityVO identityOf(CurrentSession current) {
        return assembler.toIdentity(current.snapshot(), props.issuer());
    }

    @Override
    public List<TenantMembershipVO> tenants(String rawToken) {
        return tenants(requireCurrent(rawToken));
    }

    @Override
    public List<TenantMembershipVO> tenants(CurrentSession current) {
        return tx.execute(status -> {
            requestContextMapper.setContext(current.userId(), null, false);
            return sessionMapper.selectTenants(current.userId());
        });
    }

    // ---------------------------------------------------------------- 切企业 CAS

    @Override
    public IdentityVO switchTenant(String rawToken, SwitchTenantDTO req) {
        CurrentSession current = requireCurrent(rawToken);
        switchTenant(current, req);
        return assembler.toIdentity(requireSnapshot(rawToken), props.issuer());
    }

    @Override
    public void switchTenant(CurrentSession current, SwitchTenantDTO req) {
        if (req == null || req.tenantId() == null || req.expectedCtxVersion() == null) {
            throw ApiException.badRequest("tenant_id 与 expected_ctx_version 必填");
        }
        UUID targetTenantId;
        try {
            targetTenantId = UUID.fromString(req.tenantId());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("tenant_id 不是合法 UUID");
        }
        try {
            tx.executeWithoutResult(status -> {
                setContext(current.userId(), targetTenantId);
                sessionMapper.switchContext(current.sessionId(), targetTenantId, req.expectedCtxVersion());
                audit(targetTenantId, current.userId(), "auth.switch_tenant", "auth_session",
                        current.sessionId().toString(),
                        Map.of("target_tenant_id", req.tenantId().toString(),
                                "expected_ctx_version", req.expectedCtxVersion()));
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw com.airagent.iam.web.error.PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 续期

    @Override
    public SessionTimersVO renew(String rawToken, RenewDTO req) {
        return renew(requireCurrent(rawToken), req);
    }

    @Override
    public SessionTimersVO renew(CurrentSession current, RenewDTO req) {
        if (req == null || req.expectedCtxVersion() == null) {
            throw ApiException.badRequest("expected_ctx_version 必填");
        }
        try {
            return tx.execute(status -> {
                setContext(current.userId(), current.currentTenantId());
                SessionTimerDO row = sessionMapper.renew(current.sessionId(), req.expectedCtxVersion(),
                        props.session().renewIdleSeconds());
                audit(current.currentTenantId(), current.userId(), "auth.renew", "auth_session",
                        current.sessionId().toString(), Map.of());
                return new SessionTimersVO(iso(row.absoluteExpiresAt()),
                        iso(row.idleExpiresAt()));
            });
        } catch (org.springframework.dao.DataAccessException e) {
            throw com.airagent.iam.web.error.PgErrorTranslator.toApiException(e);
        }
    }

    // ---------------------------------------------------------------- 改密

    @Override
    public void changePassword(String rawToken, ChangePasswordDTO req) {
        changePassword(requireCurrent(rawToken), req);
    }

    @Override
    public void changePassword(CurrentSession current, ChangePasswordDTO req) {
        if (req == null || req.oldPassword() == null || req.newPassword() == null) {
            throw ApiException.badRequest("old_password 与 new_password 必填");
        }
        if (req.newPassword().length() < 8 || req.newPassword().length() > 256) {
            throw ApiException.badRequest("新口令长度需在 8 到 256 字符之间");
        }
        if (req.newPassword().equals(req.oldPassword())) {
            throw ApiException.conflict("新口令不得与旧口令相同");
        }

        // 旧哈希取自主权快照（to_jsonb 行含 password_hash，仅在服务端内存中比对，不进日志/响应）
        JsonNode hashNode = current.snapshot().raw().path("user").path("password_hash");
        String storedHash = hashNode.isTextual() ? hashNode.asText() : null;
        if (!passwordHasher.matches(req.oldPassword(), storedHash)) {
            throw ApiException.unauthenticated("旧口令不正确");
        }
        String newHash = passwordHasher.hash(req.newPassword());

        tx.executeWithoutResult(status -> {
            setContext(current.userId(), current.currentTenantId());
            List<String> digests = sessionMapper.revokeUserSessions(current.userId(), "user.password_change");
            if (!digests.isEmpty()) {
                enqueueRedisDelete(digests.stream().map(this::redisKey).toList());
            }
            sessionMapper.setPassword(current.userId(), newHash);
            audit(current.currentTenantId(), current.userId(), "auth.change_password",
                    "user", current.userId().toString(),
                    Map.of("revoked_sessions", digests.size()));
        });
        bestEffortRedisDeleteBySession(current.sessionId());
    }

    // ---------------------------------------------------------------- 权威核验

    /**
     * 双重核验：Redis Sa-Token 会话存在（依赖故障向上抛 503），PG 主库快照状态可用。
     */
    @Override
    public AuthoritySnapshot requireSnapshot(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw ApiException.unauthenticated("缺少访问令牌");
        }
        Object loginId;
        try {
            loginId = StpUtil.getStpLogic().getLoginIdByToken(rawToken);
        } catch (NotLoginException e) {
            throw ApiException.unauthenticated("未认证或会话已失效");
        }
        if (loginId == null) {
            throw ApiException.unauthenticated("会话不存在或已撤销");
        }
        return snapshotFromDigest(OpaqueTokens.digest(rawToken), loginId);
    }

    @Override
    public CurrentSession requireCurrent(String rawToken) {
        return toCurrent(requireSnapshot(rawToken));
    }

    /**
     * 浏览器 /web-api 链路：句柄只映射到 session id（原始令牌不入浏览器/句柄表）。
     * 服务端经 SECURITY DEFINER 取回该会话令牌摘要后，走与 Bearer 完全相同的
     * "Redis 存活 + PG 主库权威快照"双重核验，不引入第二权威。
     */
    @Override
    public CurrentSession requireCurrentBySessionId(UUID sessionId) {
        if (sessionId == null) {
            throw ApiException.unauthenticated("缺少浏览器会话句柄");
        }
        String digest = sessionMapper.selectTokenDigest(sessionId);
        if (digest == null) {
            throw ApiException.unauthenticated("会话不存在或已撤销");
        }
        Object loginId = ((DigestStpLogic) StpUtil.getStpLogic()).getLoginIdByDigest(digest);
        if (loginId == null) {
            throw ApiException.unauthenticated("会话不存在或已撤销");
        }
        return toCurrent(snapshotFromDigest(digest, loginId));
    }

    private AuthoritySnapshot snapshotFromDigest(String digest, Object redisLoginId) {
        AuthoritySnapshot snapshot = loadSnapshot(digest);
        UUID sessionUserId = snapshot.userId();
        if (sessionUserId == null || !redisLoginId.toString().equals(sessionUserId.toString())) {
            throw ApiException.unauthenticated("会话与登录主体不一致");
        }
        if (!snapshot.usable()) {
            throw mapInactive(snapshot.status());
        }
        return snapshot;
    }

    private CurrentSession toCurrent(AuthoritySnapshot snapshot) {
        return new CurrentSession(
                snapshot.sessionId(),
                snapshot.userId(),
                snapshot.realm(),
                snapshot.loginAudience(),
                snapshot.currentTenantId(),
                snapshot.ctxVersion(),
                snapshot);
    }

    /**
     * 权威快照加载。tenants/membership_roles 等为 FORCE RLS，SECURITY DEFINER 函数内读取
     * 仍受调用方 GUC 约束，因此必须先用会话自身身份（取自非 FORCE 的 auth_sessions）建立
     * 事务级请求上下文，再取快照；上下文只精确到该会话的 user/current_tenant。
     */
    @Override
    public AuthoritySnapshot loadSnapshot(String digest) {
        // 此函数在单个 SQL 语句内推导并恢复可信上下文，不需要占用外层只读事务连接。
        String json = sessionMapper.loadSnapshotJson(digest);
        try {
            return AuthoritySnapshot.of(mapper.readTree(json));
        } catch (RuntimeException ex) {
            throw ApiException.dependencyUnavailable("身份快照解析失败");
        }
    }

    private ApiException mapInactive(String status) {
        return switch (status) {
            case "missing", "invalid_or_revoked" ->
                    ApiException.unauthenticated("会话无效或已被撤销");
            case "account_disabled" -> ApiException.unauthenticated("账号已停用");
            case "tenant_suspended" -> ApiException.forbidden("所属企业已停用");
            case "membership_disabled" -> ApiException.forbidden("企业成员关系已停用");
            default -> ApiException.unauthenticated("会话不可用");
        };
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * 设置事务级请求上下文（GUC local=true，事务结束自动重置）。
     * 平台级行（tenant_id 为空）以平台身份写；企业行以该租户身份写，RLS 复合约束不放宽。
     */
    private void setContext(UUID userId, UUID tenantId) {
        requestContextMapper.setContext(userId, tenantId, tenantId == null);
    }

    private void validateLogin(LoginDTO req) {
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.account() == null || req.account().length() < 3 || req.account().length() > 64
                || !req.account().matches("\\p{Graph}{3,64}")) {
            throw ApiException.badRequest("account 不合法");
        }
        if (req.password() == null || req.password().length() < 8 || req.password().length() > 256) {
            throw ApiException.badRequest("password 不合法");
        }
        if (!"workforce".equals(req.realm())) {
            throw ApiException.badRequest("realm 仅支持 workforce");
        }
        if (!AUDIENCES.contains(req.audience())) {
            throw ApiException.badRequest("audience 不合法");
        }
    }

    @Override
    public void audit(UUID tenantId, UUID actor, String action, String targetType, String targetId,
                      Map<String, Object> detail) {
        try {
            String detailJson = mapper.writeValueAsString(detail == null ? Map.of() : detail);
            eventMapper.insertAudit(tenantId, actor, action, targetType, targetId, detailJson,
                    org.slf4j.MDC.get("request_id"));
        } catch (Exception e) {
            throw new IllegalStateException("审计写入失败（事务必须整体回滚）", e);
        }
    }

    private void enqueueRedisDelete(List<String> keys) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("keys", keys);
        try {
            String json = mapper.writeValueAsString(payload);
            eventMapper.enqueueRedisDeletes(json);
        } catch (Exception e) {
            throw new IllegalStateException("outbox 登记失败（事务必须整体回滚）", e);
        }
    }

    private String redisKey(String digest) {
        return ((DigestStpLogic) StpUtil.getStpLogic()).keyByDigest(digest);
    }

    /**
     * 浏览器链路无原始令牌：按会话 id 取回摘要后立即删 Sa-Token 键。
     * PG 撤销即权威拒绝；Redis 残留由 outbox 重放兜底，清理失败不回滚事务。
     */
    private void bestEffortRedisDeleteBySession(UUID sessionId) {
        try {
            String digest = sessionMapper.selectTokenDigest(sessionId);
            if (digest != null) {
                ((DigestStpLogic) StpUtil.getStpLogic()).deleteByDigest(digest);
            }
        } catch (RuntimeException e) {
            LOGGER.warn("按会话摘要立即清理 Redis 失败，等待 outbox 重放 requestId={}",
                    org.slf4j.MDC.get("request_id"));
        }
    }

    private String iso(OffsetDateTime value) {
        return value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }
}
