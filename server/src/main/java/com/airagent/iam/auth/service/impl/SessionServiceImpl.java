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
 * {@link SessionService} 实现：登录、SSO 兑换、退出/全退、身份、企业列表、
 * 切企业 CAS、续期与本人改密（Service 层，auth 模块的唯一权威入口）。
 *
 * <p>编排模式与 admin 线一致：读路径以 {@code rawToken} 做"Redis Sa-Token 存活 + PG 主库权威快照"
 * 双重核验（{@link #requireSnapshot(String)}），写路径再经 {@link TransactionTemplate} 开事务，
 * 事务第一步用 {@link RequestContextMapper#setContext} 把 GUC 上下文精确设到该会话的
 * user/current_tenant（{@code tenantId} 为空即平台身份），随后同事务完成状态变更、审计
 * 与 Redis 清理 outbox 登记。数据库函数抛出的 SQLSTATE 由
 * {@link com.airagent.iam.web.error.PgErrorTranslator} 翻译，其余依赖类异常冒泡到
 * {@link com.airagent.iam.web.error.GlobalExceptionHandler} 转 503。
 *
 * <p>职责边界（Redis 与 PG）：PG 的 {@code iam.auth_sessions} 是会话与授权的唯一权威，
 * Redis 只是 Sa-Token 的存活索引，键名为访问令牌摘要（见 {@link DigestStpLogic}）。
 * 撤销的权威判定始终来自 PG——Redis 未清理成功也只是残留；反之 Redis 故障或被暂停时，
 * 核验与限流都以失败关闭（503），绝不因"读不到"而放行，也没有任何跨请求的正向授权缓存。
 *
 * <p>失效判定：会话基线 {@code base_user_revision} / {@code base_tenant_revision} /
 * {@code base_membership_revision} 在登录与切企业时冻结，快照中当前代次高于基线即判定旧快照失效；
 * 会话纪元 {@code ctx_version} 只随切企业递增，是续期与切企业的 CAS 基线。
 * 时限由数据库判定：绝对上限不可延长，空闲窗口在持锁后单调取大并夹在绝对上限内。
 * 本人改密与全局登出会撤销该用户全部会话（含当前会话），管理员重置与停用走 admin 线的同名函数。
 *
 * <p>投递语义：Redis 键删除经 {@code iam.outbox} 至少一次投递，由
 * {@link com.airagent.iam.auth.OutboxRelay} 重放，删除操作本身幂等。
 *
 * @author Acerola
 */
@Service
public class SessionServiceImpl implements SessionService {

    /** 会话与补偿清理过程的告警日志，不记录令牌、摘要或口令。 */
    private static final Logger LOGGER = LoggerFactory.getLogger(SessionServiceImpl.class);

    /**
     * 登录允许的受众白名单，与数据库 {@code mint_sso_session} / {@code sso_clients} 的
     * CHECK 约束一致：不在此集合内的取值在进入数据库前即 400，不产生新的受众通道。
     */
    private static final Set<String> AUDIENCES = Set.of("air-agent", "knowledge", "iam-admin");

    /** 会话状态机与权威快照的 SQL 网关（全部经 iam_auth 的 SECURITY DEFINER 函数）。 */
    private final SessionMapper sessionMapper;

    /** 事务级 RLS 请求上下文写入器，是数据库侧识别"当前操作者"的唯一途径。 */
    private final RequestContextMapper requestContextMapper;

    /** 审计与 outbox 登记（与业务变更同事务，失败即整体回滚）。 */
    private final AdminEventMapper eventMapper;

    /** 编程式事务边界；本类不使用声明式 {@code @Transactional}。 */
    private final TransactionTemplate tx;

    /** BCrypt 摘要生成与比对；口令只在方法栈内短暂存在。 */
    private final PasswordHasher passwordHasher;

    /** 权威快照到 {@link IdentityVO} 的投影装配器。 */
    private final IdentityAssembler assembler;

    /** {@code iam.*} 配置：签发方标识、会话时限与 outbox 参数。 */
    private final IamProperties props;

    /** jsonb 文本解析与 detail/payload 序列化。 */
    private final ObjectMapper mapper;

    /** 登录准入限流（按 {@code realm:account} 固定窗口）；Redis 故障时失败关闭。 */
    private final com.airagent.iam.security.internal.RateLimiter rateLimiter;

    /**
     * 构造会话权威实现，全部依赖经 Spring 构造注入。
     *
     * @param sessionMapper        会话状态机与快照的数据访问
     * @param requestContextMapper RLS 请求上下文写入器
     * @param eventMapper          审计与 outbox 登记
     * @param tx                   编程式事务边界
     * @param passwordHasher       口令摘要生成与比对
     * @param assembler            身份视图装配器
     * @param props                {@code iam.*} 配置
     * @param mapper               jsonb 与 detail 的序列化器
     * @param rateLimiter          登录限流器
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：形状校验 → 限流（{@code realm:account} 固定窗口，先于 BCrypt，
     * 避免口令校验被当成廉价探测面）→ {@link SessionMapper#findLogin} 取摘要 →
     * {@link PasswordHasher#matches} 比对。账号不存在、状态非 active、摘要不匹配三种情况
     * 折叠为同一句 {@code 账号或口令错误} 的 401，日志与响应都不含账号之外的输入。
     *
     * <p>随后先建 Redis 会话（原始令牌由 {@link OpaqueTokens#newRawToken} 生成，
     * Sa-Token 侧以摘要为键、绝对时限为 TTL，不写响应头且允许并发会话），再在事务内
     * {@link SessionMapper#createSession} 写 PG 权威行并登记 {@code auth.login} 审计；
     * PG 失败则补偿删除刚建的 Redis 会话后原样抛出。最后回读权威快照并校验其会话 id
     * 与刚建的一致——不一致说明两条链路指向不同行，按依赖不可用拒绝返回该令牌。
     */
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
     * {@inheritDoc}
     *
     * <p>实现细节：SSO 兑换成功后为同一人类签发独立的受众应用会话（受众绑定注册客户端，
     * 兑换端点已完成客户端凭据与回调/Origin 裁决）。仅 {@code workforce} 人类会话可用，否则 403。
     *
     * <p>新会话以 {@link SessionMapper#mintSsoSession} 挂在源会话所属的中央会话之下：
     * 复制中央会话的当前企业、上下文代次与三项授权基线，时限取自身窗口与中央剩余时间的较小值，
     * 因此子会话不会比中央会话活得更久，且中央退出/切企业/续期会经数据库触发器原子传播过来。
     * Redis 先建、PG 后写，PG 失败同样补偿删除新令牌；此处不再断言回读快照的会话 id
     * 与某一行相等（不同于登录路径），身份视图直接按新令牌的快照装配。
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先按令牌做双重核验，仅吞掉 401（无令牌/会话已撤销或过期/代次变旧），
     * 视作"已经处于登出状态"直接返回；403（企业或成员关系停用）与 503 照常抛出，
     * 以免把依赖故障伪装成登出成功。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：事务内以会话自身身份设置上下文，撤销单个会话（原因 {@code user.logout}）；
     * 函数返回非空摘要才登记 outbox（已撤销的会话返回 {@code null}，不重复清理）。
     * 提交后另按会话 id 取回摘要即时删除 Redis 键（{@link #bestEffortRedisDeleteBySession}），
     * 使下一次读取立刻消失；即时删除失败不回滚，权威拒绝已由 PG 撤销保证。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：与 {@link #logout(String)} 不同，这里不吞任何核验错误——全退是改变状态的
     * 操作，令牌不可用时按 401 明确拒绝，避免调用方误以为"已登出全部设备"。
     */
    @Override
    public void logoutAll(String rawToken) {
        logoutAll(requireCurrent(rawToken));
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：以平台身份（上下文租户为空）执行
     * {@link SessionMapper#revokeUserSessions}，函数把该用户全部活跃会话置 revoked
     * （含当前会话与 SSO 兑换出的子会话）并额外将 {@code users.auth_revision} +1；
     * 摘要批量映射为 Sa-Token 键名后一次登记 outbox，审计 detail 只记撤销数量。
     * 提交后仍按当前会话 id 做一次即时 Redis 删除作为快速路径。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：核验与装配在同一次调用内完成，快照不落任何缓存，
     * 因此 {@code /me} 每次都是一次 Redis 存活检查加一次主库单往返。
     */
    @Override
    public IdentityVO me(String rawToken) {
        return assembler.toIdentity(requireSnapshot(rawToken), props.issuer());
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：直接用快照自带权限视图装配，不触发额外数据库往返，
     * 适合同一请求内已核验后的重复读取（浏览器链路与 SSO 授权页）。
     */
    @Override
    public IdentityVO identityOf(CurrentSession current) {
        return assembler.toIdentity(current.snapshot(), props.issuer());
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先做双重核验再委托会话快照重载。
     */
    @Override
    public List<TenantMembershipVO> tenants(String rawToken) {
        return tenants(requireCurrent(rawToken));
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：直读 FORCE RLS 的 tenants/tenant_memberships/membership_roles，
     * 因此在事务内先把上下文设为该用户自身且平台标志关闭——与其余方法的
     * {@code setContext(userId, tenantId)} 助手不同，这里刻意不传租户也不开平台身份，
     * 否则可见范围会被收窄或放宽。结果只含活跃企业与活跃成员关系，按企业 code 升序。
     */
    @Override
    public List<TenantMembershipVO> tenants(CurrentSession current) {
        return tx.execute(status -> {
            requestContextMapper.setContext(current.userId(), null, false);
            return sessionMapper.selectTenants(current.userId());
        });
    }

    // ---------------------------------------------------------------- 切企业 CAS

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：CAS 成功后按同一令牌重新加载权威快照再装配身份，因此返回体中的
     * {@code context_version}、企业与权限均为切换后的实时值，调用方须以它替换本地基线。
     */
    @Override
    public IdentityVO switchTenant(String rawToken, SwitchTenantDTO req) {
        CurrentSession current = requireCurrent(rawToken);
        switchTenant(current, req);
        return assembler.toIdentity(requireSnapshot(rawToken), props.issuer());
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：UUID 解析与必填校验在事务外完成（400）；事务内以目标企业为上下文执行
     * {@link SessionMapper#switchContext}，其内部持中央会话行锁并依次裁决会话可用性、
     * 纪元基线（P0010→409）与目标企业/成员关系（P0012→403）。数据库抛出的
     * {@code DataAccessException} 在此就地翻译，保证浏览器链路（不经过控制器）语义一致。
     * 审计 {@code auth.switch_tenant} 的 detail 只含目标企业 id 与提交的基线代次。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：核验令牌后委托会话快照重载。
     */
    @Override
    public SessionTimersVO renew(String rawToken, RenewDTO req) {
        return renew(requireCurrent(rawToken), req);
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：续期增量取配置 {@code iam.session.renew-idle-seconds}（单位秒），
     * 由数据库在持锁后用 {@code clock_timestamp()} 计算，Java 侧不参与时间推导；
     * 返回的两个时刻统一转 UTC ISO-8601 文本。会话不存在或已撤销/过期为 28000→401，
     * 纪元不符为 P0010→409，两者都不可复活、不可越过绝对上限。
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：核验令牌后委托会话快照重载；口令校验失败与令牌失效同为 401，
     * 响应消息不区分二者来源之外的额外信息。
     */
    @Override
    public void changePassword(String rawToken, ChangePasswordDTO req) {
        changePassword(requireCurrent(rawToken), req);
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：新口令长度与"新旧相同"检查都在哈希与数据库访问之前完成（分别 400/409）；
     * 旧摘要取自本请求已加载的权威快照 {@code user.password_hash}——该列对 iam_app 不可直读，
     * 只能由 SECURITY DEFINER 快照带出，仅在本次内存比对中使用，不进日志、响应与审计 detail。
     *
     * <p>事务内顺序为先 {@link SessionMapper#revokeUserSessions}（原因
     * {@code user.password_change}，全撤含当前会话并额外推进授权代次）、再
     * {@link SessionMapper#setPassword} 写新摘要（触发器因口令变化再推进一次代次），
     * 因此改密后本次登录的令牌立即不可用，调用方必须引导重新登录。被撤会话的 Redis 键删除
     * 同事务入 outbox，提交后再按会话 id 即时删除一次；此路径不做 {@code align_session_user_revision}
     * 基线对齐，即不存在"改密后保留当前会话"的行为。
     */
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
     * {@inheritDoc}
     *
     * <p>实现细节：顺序固定为"Redis 存活 → PG 权威 → 主体一致性"。
     * {@code NotLoginException}（令牌在 Redis 无对应会话、已过期或被删除）译为 401；
     * Redis 连接类异常不在这里捕获，冒泡后由全局处理器转 503——依赖不可用绝不降级为放行。
     * 拿到 loginId 后才按令牌摘要加载主库快照，并拒绝 Redis 主体与 PG 会话主体不一致的令牌。
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：核验通过后把快照投影为请求作用域会话对象，不产生额外数据库往返。
     */
    @Override
    public CurrentSession requireCurrent(String rawToken) {
        return toCurrent(requireSnapshot(rawToken));
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：浏览器 {@code /web-api} 链路的句柄只映射到会话 id（原始令牌既不进浏览器、
     * 也不存句柄表）。服务端经 {@link SessionMapper#selectTokenDigest} 取回该会话的令牌摘要，
     * 再用 {@link DigestStpLogic#getLoginIdByDigest} 走与 Bearer 同构的 Redis 键路径核验存活，
     * 最后按摘要加载 PG 快照——同一套权威判定，不引入第二权威。
     * 摘要缺失（会话 id 无对应行）与 Redis 键缺失同样折叠为 401，不区分以避开探测会话是否存在。
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

    /**
     * 把 PG 快照与 Redis 登录主体合并校验，得到可放行的权威快照。
     *
     * <p>先比对主体：快照缺 user id 或 Redis 的 loginId 与快照主体不一致即 401，
     * 防止令牌与账号错配后被当成同一主体放行。再判定可用性，不可用时按快照给出的
     * 状态映射为对应 HTTP 语义。
     *
     * @param digest       令牌摘要，用于加载 PG 权威快照
     * @param redisLoginId Redis 侧 Sa-Token 的登录主体（字符串形式的用户 id）
     * @return 判定为可用且主体一致的权威快照
     * @throws ApiException 401 主体不一致或会话/账号类不可用；403 企业或成员关系停用
     */
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

    /**
     * 权威快照 → 请求作用域会话快照的投影，字段一一对应，不做二次推导。
     *
     * @param snapshot 已判定可用的权威快照
     * @return 携带同一快照的 {@link CurrentSession}
     */
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
     * {@inheritDoc}
     *
     * <p>实现细节：tenants/membership_roles 等为 FORCE RLS，SECURITY DEFINER 函数内读取
     * 仍受调用方 GUC 约束，因此必须先有可信上下文。这里走 V18 引入的
     * {@code iam_auth.load_trusted_authority_snapshot}：函数在单条 SQL 内按摘要定位会话、
     * 依据会话自身推导上下文、读取快照后再恢复原上下文，因此无需外层预先设置 GUC，
     * 也不在外层事务里做多次往返。返回值是 jsonb 文本，解析失败按依赖不可用处理。
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

    /**
     * 把数据库给出的不可用状态映射为对外的 {@link ApiException}。
     *
     * <p>映射口径：会话缺失/被撤销/代次变旧/超时限与账号停用一律 401（不区分，避免枚举）；
     * 企业停用与成员关系停用是"主体仍有效但当前上下文被禁"，故 403；
     * 未知状态按最严格的未认证处理，绝不默认放行。
     *
     * @param status {@link AuthoritySnapshot#status()} 的不可用取值
     * @return 待抛出的异常（调用方负责 {@code throw}）
     */
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
     * 设置事务级请求上下文（GUC {@code local = true}，事务结束自动重置，不跨事务泄漏）。
     *
     * <p>平台级行（租户为空）以平台身份写，企业行以该租户身份写；RLS 的复合约束不因此放宽。
     * 上下文只是可见性开关，不是授权来源——权限仍由快照与调用方裁决。
     *
     * @param userId   已认证用户 UUID
     * @param tenantId 当前企业 UUID；{@code null} 表示平台级上下文
     */
    private void setContext(UUID userId, UUID tenantId) {
        requestContextMapper.setContext(userId, tenantId, tenantId == null);
    }

    /**
     * 登录请求的形状校验，在任何口令计算与数据库访问之前执行。
     *
     * <p>账号必须匹配可打印 ASCII 3..64（与 {@code iam.users} 的 CHECK 一致，避免把
     * 必然违反约束的输入打到数据库）；口令长度 8..256；realm 当前仅 {@code workforce}；
     * audience 必须落在 {@link #AUDIENCES} 白名单内。
     *
     * @param req 待校验的登录请求
     * @throws ApiException 400 请求体缺失或任一字段不合法（消息只指出字段名，不回显取值）
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：detail 序列化为 jsonb 文本后交 {@code iam_auth.write_audit}
     * （{@code actor_type} 固定 human），request id 取当前 MDC；任何序列化或写入失败都
     * 转成 {@link IllegalStateException} 迫使调用方事务整体回滚——不存在"业务成功、审计丢失"。
     * 审计内容禁止包含口令、令牌与密钥，只允许 id、数量与原因码类字段。
     */
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

    /**
     * 把待删除的 Redis 键登记为同事务 outbox 事件（{@code kind = redis_delete_keys}）。
     *
     * @param keys 完整 Sa-Token Redis 键名列表（由令牌摘要拼接，不含原始令牌），非空
     * @throws IllegalStateException 序列化或登记失败，调用方事务随之整体回滚
     */
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

    /**
     * 由令牌摘要拼接 Sa-Token 的 Redis 键名，供 outbox 重放与即时清理复用。
     *
     * <p>必须与令牌解析路径同构（{@link DigestStpLogic#keyByDigest}），否则删除会打空键、
     * 残留会话在 Redis 侧继续存在。
     *
     * @param digest 令牌摘要
     * @return 完整 Redis 键名
     */
    private String redisKey(String digest) {
        return ((DigestStpLogic) StpUtil.getStpLogic()).keyByDigest(digest);
    }

    /**
     * 浏览器链路无原始令牌：按会话 id 取回摘要后立即删 Sa-Token 键。
     *
     * <p>PG 撤销即权威拒绝，Redis 残留只影响"多一次无效读"，因此由 outbox 重放兜底；
     * 这里捕获运行时异常仅告警，清理失败不回滚已提交的业务事务，也不改变调用方看到的成功语义。
     *
     * @param sessionId 已撤销的会话 UUID；摘要查不到（会话行不存在）时静默跳过
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

    /**
     * 时间戳统一按 UTC 瞬时等值转换后输出 ISO-8601 文本，与身份视图的时间口径一致。
     *
     * <p>数据库列是 {@code timestamptz}，此处只换偏移、不做时区解释，因此不改变绝对时刻。
     *
     * @param value 数据库返回的时间戳；{@code null} 表示该列无值
     * @return UTC ISO-8601 文本；入参为 {@code null} 时返回 {@code null}
     */
    private String iso(OffsetDateTime value) {
        return value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }
}
