package com.airagent.iam.internal.service.impl;

import cn.dev33.satoken.stp.StpUtil;
import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.auth.IdentityAssembler;
import com.airagent.iam.auth.mapper.SessionMapper;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.internal.dto.RevisionsDTO;
import com.airagent.iam.internal.entity.IssuedVerificationRefDO;
import com.airagent.iam.internal.entity.VerificationRefDO;
import com.airagent.iam.internal.mapper.IdentityMapper;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.vo.ExecutionContextVO;
import com.airagent.iam.internal.vo.InactiveIntrospectionVO;
import com.airagent.iam.internal.vo.RecheckActiveVO;
import com.airagent.iam.internal.vo.RecheckInactiveVO;
import com.airagent.iam.internal.vo.ServiceIdentityVO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.security.satoken.DigestStpLogic;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * {@link IntrospectionService} 实现：普通令牌模式（人类 / 服务账号）与执行引用复查模式。
 *
 * <p>分层位置：Service 层，数据访问只经 {@link IdentityMapper} 与
 * {@link SessionMapper}（均为 {@code iam_auth} schema 的 {@code SECURITY DEFINER} 函数调用），
 * 身份视图装配委托给 {@link IdentityAssembler}，本类只做判定分支编排、不写 SQL。
 *
 * <p>每次调用读 PG 主库；人类主体同时检查 Redis 会话存活，不缓存跨请求授权结果。
 * 判定权在数据库：会话状态、账号/企业/成员状态、idle 与绝对到期、三项授权代次是否高于
 * 会话登记基线，全部由 {@code load_authority_snapshot}（V3 引入、V12 扩展）给出结论，
 * 本类只把 {@code status} 映射为对外 reason，绝不自行推断"应该还能用"。
 *
 * <p>active / inactive 的真实边界：
 * <ul>
 *   <li>PG 快照 {@code status != ok} → {@code active:false}（HTTP 仍 200，消费方自行映射 401/403）；</li>
 *   <li>PG 判 {@code ok} 但 Redis 中该摘要的 Sa-Token 已不存在或登录用户不符 → 同样
 *       {@code active:false}，reason 归一为 {@code invalid_or_revoked}；</li>
 *   <li>受众：请求受众必须已登记在客户端白名单；除 {@code langgraph-runtime} 这一受控派生受众外，
 *       还必须等于会话登录受众，否则 403（不是 inactive）；</li>
 *   <li>非管理受众（受众不是 {@code iam-admin}）的身份视图不返回平台角色与平台管理标记，
 *       并剔除 {@code platform:*} 与 {@code entitlement:manage} 权限码——见
 *       {@link IdentityAssembler#toIdentityForIntrospection}。</li>
 * </ul>
 *
 * <p>失败关闭：UUID 不合法、形态不合法、runtime 专属字段被他用一律 400/403；
 * 引用登记与修订解析等依赖故障抛 503，不降级为放行。
 *
 * @author Acerola
 */
@Service
public class IntrospectionServiceImpl implements IntrospectionService {

    /** 权威快照与机器身份读取（引用登记、引用复查、服务账号内省）。 */
    private final IdentityMapper identityMapper;
    /** 人类会话侧读取：按令牌摘要取权威快照、按会话 id 取令牌摘要。 */
    private final SessionMapper sessionMapper;
    /** 编程式事务边界：引用复查把"读引用 + 读权威快照 + 比修订"收敛在同一次主库往返内。 */
    private final TransactionTemplate tx;
    /** 权威快照 → iam.identity.v1 视图的装配器（按受众裁剪权限与平台角色）。 */
    private final IdentityAssembler assembler;
    /** {@code iam.*} 配置：签发方标识与引用 TTL（秒）。 */
    private final IamProperties props;
    /** Jackson 实例：快照 jsonb 解析、修订序列化与 identity 到 Map 的转换。 */
    private final ObjectMapper mapper;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param identityMapper 执行引用与机器身份的数据访问
     * @param sessionMapper  人类会话快照与令牌摘要读取
     * @param tx             编程式事务边界（本类不使用声明式 {@code @Transactional}）
     * @param assembler      身份视图装配器
     * @param props          配置属性（issuer、{@code iam.internal.*}）
     * @param mapper         JSON 读写组件（全局 SNAKE_CASE 策略）
     */
    public IntrospectionServiceImpl(IdentityMapper identityMapper, SessionMapper sessionMapper,
                                   TransactionTemplate tx,
                                IdentityAssembler assembler, IamProperties props, ObjectMapper mapper) {
        this.identityMapper = identityMapper;
        this.sessionMapper = sessionMapper;
        this.tx = tx;
        this.assembler = assembler;
        this.props = props;
        this.mapper = mapper;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先校验请求形态（{@code audience} 必填、令牌与引用二选一），再校验
     * 受众是否落在客户端注册白名单（403），最后按 {@code executionContext} 是否出现分派到
     * 复查模式或令牌模式。受众检查先于主体核验，因此未注册受众的探测不会触达主体。
     */
    @Override
    public Object introspect(InternalClient client, IntrospectDTO req) {
        validateShape(req);
        if (!client.hasAudience(req.audience())) {
            throw ApiException.forbidden("客户端未注册该受众: " + req.audience());
        }
        if (req.executionContext() != null) {
            return recheckExecutionContext(client, req);
        }
        return introspectSubjectToken(client, req);
    }

    // ---------------------------------------------------------------- token 模式

    /**
     * 令牌模式：核验一个不透明令牌，返回身份视图或 inactive 信封。
     *
     * <p>分支顺序即判定链：
     * <ol>
     *   <li>按摘要读人类会话快照；状态为 {@code missing}（该摘要根本不是人类会话）时转入
     *       服务账号分支，由机器身份函数给出自己的结论；</li>
     *   <li>人类快照不可用 → {@link #inactive(String)} 映射后的 {@code active:false}（HTTP 200）；</li>
     *   <li>{@code include_execution_context} 只允许 runtime 受众（否则 400）；</li>
     *   <li>受众匹配：runtime 是可跨登录受众的受控派生受众，其余受众必须等于会话登录受众，
     *       否则 403——防止用 A 应用的令牌核验出 B 应用的身份；</li>
     *   <li>{@code expected_context} 基线比对：会话必须已选企业且企业与上下文代次同时相等，
     *       否则 409 且响应不回新上下文（失败关闭，避免旧缓存被静默续用）；</li>
     *   <li>装配按受众裁剪的 {@link IdentityVO}；需要执行上下文时再登记引用并把
     *       {@code execution_context} 合并进同一 JSON 对象返回。</li>
     * </ol>
     *
     * @param client 已认证的内部客户端（提供注册受众白名单，引用登记时作为归属主体写入）
     * @param req    已通过形态与受众白名单校验的请求；{@code subjectToken} 非空白
     * @return {@link IdentityVO}；携带执行上下文时为 identity 字段与 {@code execution_context}
     *         键合并后的 {@link LinkedHashMap}；主体失效时为 {@link InactiveIntrospectionVO}
     */
    private Object introspectSubjectToken(InternalClient client, IntrospectDTO req) {
        String digest = OpaqueTokens.digest(req.subjectToken());
        AuthoritySnapshot snapshot = loadHumanSnapshot(digest);

        if ("missing".equals(snapshot.status())) {
            return introspectServiceAccount(client, req, digest);
        }
        if (!snapshot.usable()) {
            return inactive(snapshot.status());
        }
        if (Boolean.TRUE.equals(req.includeExecutionContext()) && !RUNTIME_AUDIENCE.equals(req.audience())) {
            throw ApiException.badRequest("include_execution_context 仅 runtime 受众客户端可用");
        }
        // runtime 是受控服务端派生受众；其他应用只能核验本应用登录的令牌。
        if (!RUNTIME_AUDIENCE.equals(req.audience()) && !req.audience().equals(snapshot.loginAudience())) {
            throw ApiException.forbidden("主体令牌受众与请求不一致");
        }
        if (req.expectedContext() != null) {
            UUID expectedTenant = parseUuid(req.expectedContext().tenantId(), "expected_context.tenant_id");
            UUID currentTenant = snapshot.currentTenantId();
            if (currentTenant == null
                    || !currentTenant.equals(expectedTenant)
                    || snapshot.ctxVersion() != safeLong(req.expectedContext().ctxVersion())) {
                // 调用方上下文过期：显式冲突、失败关闭（不返回新上下文细节）
                throw ApiException.contextChanged("expected_context 与当前会话上下文不一致");
            }
        }

        IdentityVO identity = assembler.toIdentityForIntrospection(snapshot, props.issuer(), req.audience());
        if (Boolean.TRUE.equals(req.includeExecutionContext())) {
            if (!RUNTIME_AUDIENCE.equals(req.audience()) || !client.hasAudience(RUNTIME_AUDIENCE)) {
                throw ApiException.badRequest("include_execution_context 仅 runtime 受众客户端可用");
            }
            ExecutionContextVO executionContext = createExecutionContext(client, req.audience(), snapshot);
            Map<String, Object> merged = mapper.convertValue(identity,
                    new tools.jackson.core.type.TypeReference<LinkedHashMap<String, Object>>() {
                    });
            merged.put("execution_context", mapper.convertValue(executionContext,
                    new tools.jackson.core.type.TypeReference<LinkedHashMap<String, Object>>() {
                    }));
            return merged;
        }
        return identity;
    }

    /**
     * 机器主体分支：把同一摘要按服务账号令牌再读一次并装配机器身份视图。
     *
     * <p>仅由 {@link #introspectSubjectToken} 在人类快照为 {@code missing} 时进入。判定完全来自
     * {@code iam_auth.load_service_identity}：凭据不存在/已撤销/已过 {@code expires_at}/
     * 已过轮换重叠窗 {@code overlap_until} → {@code invalid_or_revoked}；服务账号非活跃或已到期
     * → {@code account_disabled}；所属企业非活跃 → {@code tenant_suspended}。
     *
     * <p>机器主体没有会话，因此不支持 {@code include_execution_context} 与
     * {@code expected_context}（携带任一即 400）；受众必须出现在服务账号自身的注册受众数组里，
     * 否则 403（与"客户端是否注册该受众"是两道独立检查）。
     *
     * @param client 已认证的内部客户端（本分支只用其受众语义，不写引用）
     * @param req    核验请求
     * @param digest 令牌摘要（SHA-256 十六进制）；原始令牌不进入本层
     * @return 有效时为 {@link ServiceIdentityVO}，否则 {@link InactiveIntrospectionVO}（HTTP 200）
     */
    private Object introspectServiceAccount(InternalClient client, IntrospectDTO req,
                                            String digest) {
        JsonNode node = loadServiceIdentity(digest);
        String status = node.path("status").asText();
        if (!"ok".equals(status)) {
            return inactive(status);
        }
        if (Boolean.TRUE.equals(req.includeExecutionContext()) || req.expectedContext() != null) {
            throw ApiException.badRequest("服务账号不支持执行上下文与 expected_context");
        }
        JsonNode sa = node.path("service_account");
        List<String> saAudiences = textList(sa.path("audiences"));
        if (!saAudiences.contains(req.audience())) {
            throw ApiException.forbidden("服务账号未注册该受众: " + req.audience());
        }
        return toServiceIdentity(node, req.audience());
    }

    /**
     * 机器身份快照 → {@link ServiceIdentityVO} 的投影。
     *
     * <p>与人类视图的差异：{@code principal.type = service_account}、{@code realm = service}，
     * {@code user}/{@code session}/{@code membership} 与四项修订一律为 {@code null}
     * （机器主体没有会话纪元）。权限码取自快照的活跃且非资源型授予，本层不再裁剪。
     *
     * @param node     {@code load_service_identity} 解析后的快照根节点（状态已确认为 {@code ok}）
     * @param audience 本次请求受众（已确认在服务账号注册受众内），回填到视图的 {@code audience}
     * @return 机器身份视图，{@code active} 恒为 {@code true}
     */
    private ServiceIdentityVO toServiceIdentity(JsonNode node, String audience) {
        JsonNode sa = node.path("service_account");
        JsonNode tenant = node.path("tenant");
        JsonNode credential = node.path("credential");
        boolean hasTenant = !tenant.isNull() && !tenant.isMissingNode();
        return new ServiceIdentityVO(
                INTROSPECTION_SCHEMA,
                true,
                props.issuer(),
                audience,
                new ServiceIdentityVO.Principal(
                        "service_account", sa.path("id").asText(), "service"),
                null,
                null,
                null,
                hasTenant
                        ? new ServiceIdentityVO.Tenant(
                                tenant.path("id").asText(), tenant.path("code").asText(),
                                tenant.path("name").asText(), tenant.path("status").asText())
                        : null,
                textList(node.path("permissions")),
                sa.path("revision").asLong(),
                credential.path("id").asText(),
                credential.path("revision").asLong(),
                credential.path("expires_at").asText(null),
                credential.path("overlap_until").asText(null),
                null,
                evaluatedAt());
    }

    // ---------------------------------------------------------------- 复查模式

    /**
     * 引用复查模式：凭已登记的 {@code verification_ref} 回读原会话的实时权威结论。
     *
     * <p>事务内的三步必须在同一次主库往返内完成（{@link TransactionTemplate} 包裹）：
     * 按 (引用 id, 客户端 id, 受众) 取引用 → 由引用里的会话 id 走与令牌摘要同一条权威路径读快照
     * → 比对三份修订（引用登记值 {@code stored}、调用方声明值 {@code supplied}、当前实时值
     * {@code current}）。任一环节不成立即返回 {@code active:false, context_matches:false}，
     * 且 HTTP 仍是 200（复查结论不是协议错误）。
     *
     * <p>{@code context_matches=false} 的真实产生条件（本模式独有，逐条对应实现）：
     * <ol>
     *   <li>引用查不到——不存在、属于其他客户端、受众不同或 {@code valid_until} 已过
     *       → reason {@code invalid_or_revoked}（伪造/越权与过期不区分，避免探测）；</li>
     *   <li>原会话权威快照不可用 → reason 取 {@link #inactive(String)} 映射结果
     *       （撤销/到期/代次变旧为 {@code invalid_or_revoked}，账号停用为
     *       {@code account_disabled}，企业停用为 {@code tenant_suspended}，
     *       成员关系停用为 {@code membership_disabled}）；</li>
     *   <li>{@code stored != supplied} 或 {@code stored != current}
     *       → reason {@code revision_mismatch}（切企业、改密、角色或成员关系变更都会落到这里）；</li>
     *   <li>事务内全部成立但 Redis 中该会话令牌摘要已不存活
     *       → reason {@code invalid_or_revoked}。</li>
     * </ol>
     *
     * <p>Redis 检查刻意放在事务之后：网络等待不占用已完成权威读取的 PostgreSQL 连接。
     * 复查不延长引用有效期，也不重新授予任何更大权限；引用的读取边界是
     * {@code find_verification_ref} 的三重匹配，会话本身的有效性边界是权威快照。
     *
     * @param client 已认证的内部客户端；{@code clientId} 与 {@code audience} 参与引用匹配
     * @param req    复查请求；{@code executionContext} 非空且四项修订齐备（否则 400）
     * @return {@link RecheckActiveVO}（{@code contextMatches} 恒为 {@code true}，并带回实时修订）
     *         或 {@link RecheckInactiveVO}
     */
    private Object recheckExecutionContext(InternalClient client, IntrospectDTO req) {
        var ec = req.executionContext();
        if (ec.verificationRef() == null || ec.verificationRef().isBlank()) {
            throw ApiException.badRequest("execution_context.verification_ref 必填");
        }
        if (ec.expectedRevisions() == null
                || ec.expectedRevisions().userAuthRevision() == null
                || ec.expectedRevisions().tenantAuthRevision() == null
                || ec.expectedRevisions().membershipRevision() == null
                || ec.expectedRevisions().sessionCtxVersion() == null) {
            throw ApiException.badRequest("expected_revisions 四项修订必填");
        }
        UUID refId = parseUuid(ec.verificationRef(), "verification_ref");

        ReferenceEvaluationBO evaluation = tx.execute(status -> {
            VerificationRefDO reference = identityMapper.findReference(refId, client.clientId(), req.audience());
            if (reference == null) {
                return ReferenceEvaluationBO.rejected("invalid_or_revoked");
            }
            UUID sessionId = reference.sessionId();
            AuthoritySnapshot snapshot = AuthoritySnapshot.of(
                    mapper.readTree(identityMapper.snapshotForSession(sessionId)));
            RevisionsDTO stored = parseRevisions(reference.revisionsJson());
            RevisionsDTO supplied = ec.expectedRevisions();
            RevisionsDTO current = currentRevisions(snapshot);
            if (!snapshot.usable()) {
                return ReferenceEvaluationBO.rejected(inactive(snapshot.status()).reason());
            }
            if (!stored.equals(supplied) || !stored.equals(current)) {
                return ReferenceEvaluationBO.rejected("revision_mismatch");
            }
            return new ReferenceEvaluationBO(new RecheckActiveVO(true, true, current, evaluatedAt()),
                    null, snapshot, sessionMapper.selectTokenDigest(sessionId));
        });
        if (evaluation.inactive() != null) {
            return evaluation.inactive();
        }
        // Redis 网络等待不占用已经完成权威读取的 PostgreSQL 连接。
        if (!redisSessionMatches(evaluation.digest(), evaluation.snapshot())) {
            return new RecheckInactiveVO(false, false, "invalid_or_revoked", evaluatedAt());
        }
        return evaluation.active();
    }

    /**
     * 事务内引用复查的评估结果（内部 BO，不出现在任何响应或日志中）。
     *
     * <p>{@code active} 与 {@code inactive} 互斥：判定通过时只有 {@code active} 非空，
     * 并额外携带原会话摘要供事务外做 Redis 存活复核；判定拒绝时只有 {@code inactive} 非空。
     *
     * @param active   复查通过结论（含实时修订）；拒绝时为 {@code null}
     * @param inactive 复查不通过结论（含 reason）；通过时为 {@code null}
     * @param snapshot 复查通过时读取到的权威快照，供 Redis 存活比对取用户 id；拒绝时为 {@code null}
     * @param digest   原会话的令牌摘要，Redis 存活性检查的键来源；拒绝时为 {@code null}
     */
    private record ReferenceEvaluationBO(RecheckActiveVO active, RecheckInactiveVO inactive,
                                           AuthoritySnapshot snapshot, String digest) {
        /**
         * 构造一个拒绝结论。
         *
         * @param reason 对外 reason 码，取值范围见
         *               {@link com.airagent.iam.internal.vo.RecheckInactiveVO#reason()}
         * @return 仅 {@code inactive} 非空的评估结果，{@code evaluatedAt} 取当前 UTC 时刻
         */
        private static ReferenceEvaluationBO rejected(String reason) {
            return new ReferenceEvaluationBO(null,
                    new RecheckInactiveVO(false, false, reason, evaluatedAt()), null, null);
        }
    }

    /**
     * 从权威快照读取当前四项修订（对应快照的 {@code revisions} 对象）。
     *
     * <p>无企业上下文时数据库以 {@code 0} 给出企业与成员代次（{@code COALESCE}），
     * 因此本方法不处理缺失节点，缺失同样读为 0。
     *
     * @param snapshot 已读取的权威快照（调用方已确认节点结构）
     * @return 当前实时的四项修订，用于与引用登记值和调用方声明值比较
     */
    private RevisionsDTO currentRevisions(AuthoritySnapshot snapshot) {
        JsonNode rev = snapshot.raw().path("revisions");
        return new RevisionsDTO(
                rev.path("user_auth_revision").asLong(),
                rev.path("tenant_auth_revision").asLong(),
                rev.path("membership_revision").asLong(),
                rev.path("session_ctx_version").asLong());
    }

    /**
     * 登记一条新的执行引用并装配对外执行上下文。
     *
     * <p>引用的修订基线就是此刻的实时值，因此后续复查只有"什么都没变"才可能通过；
     * 上界由数据库取 {@code min(now + TTL, 会话绝对到期)}——TTL 来自
     * {@code iam.internal.verification-ref-ttl-seconds}（默认 43200 秒），
     * 与 60 秒的 rt-v1 入口票据互不影响，也不能延长身份。
     * 同一会话可重复登记多条引用，复查不会消费旧引用。
     *
     * @param client   登记归属的客户端（写入引用行，决定后续谁能查到）
     * @param audience 引用绑定的受众，复查请求必须给出同一受众
     * @param snapshot 已判为可用的权威快照，提供会话、用户、当前企业与实时修订
     * @return 执行上下文视图；引用行不含任何令牌或密钥材料
     */
    private ExecutionContextVO createExecutionContext(InternalClient client, String audience,
                                                        AuthoritySnapshot snapshot) {
        RevisionsDTO revisions = currentRevisions(snapshot);
        String revisionsJson;
        try {
            revisionsJson = mapper.writeValueAsString(revisions);
        } catch (Exception e) {
            throw ApiException.dependencyUnavailable("修订序列化失败");
        }
        IssuedVerificationRefDO row = identityMapper.createReference(client.clientId(), audience,
                snapshot.sessionId(), snapshot.userId(), snapshot.currentTenantId(), revisionsJson,
                props.internal().verificationRefTtlSeconds());
        return new ExecutionContextVO(
                row.id().toString(),
                audience,
                snapshot.sessionId().toString(),
                revisions,
                row.validUntil().withOffsetSameInstant(ZoneOffset.UTC).toString());
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：单次主库往返读快照，仅当快照判 {@code ok} 时才追加 Redis 存活检查
     * （失效主体不必再触 Redis）；Redis 不存活时保留原始 JSON、只把 {@code status}
     * 改写为 {@code invalid_or_revoked}，使调用方拿到统一的失败语义而不泄露内部区分。
     */
    @Override
    public AuthoritySnapshot loadHumanSnapshot(String digest) {
        AuthoritySnapshot snapshot = AuthoritySnapshot.of(mapper.readTree(sessionMapper.loadSnapshotJson(digest)));
        if (snapshot.usable() && !redisSessionMatches(digest, snapshot)) {
            return new AuthoritySnapshot("invalid_or_revoked", snapshot.raw());
        }
        return snapshot;
    }

    @Override
    public boolean tenantIsActive(UUID tenantId) {
        return tenantId != null && identityMapper.tenantIsActive(tenantId);
    }

    /**
     * 校验令牌摘要在 Redis 中的 Sa-Token 存活记录是否仍指向快照里的同一用户。
     *
     * <p>这是"PG 权威 + Redis 存活"双检中的第二检：PG 说会话活跃但 Redis 键已被删除
     * （登出、撤销、清理）时一律判不可用。按摘要反查登录 id 走与 {@code getLoginIdByToken}
     * 同构的路径，原始令牌不出现在本层。
     *
     * @param digest   令牌摘要；{@code null} 视为不存活
     * @param snapshot 权威快照，提供用于比对的 {@code userId}；{@code userId} 为 {@code null}
     *                 （状态非 {@code ok} 的快照）时同样视为不存活
     * @return 摘要存在对应 Sa-Token 记录且登录 id 与快照用户 id 文本相等时为 {@code true}
     */
    private boolean redisSessionMatches(String digest, AuthoritySnapshot snapshot) {
        if (digest == null || snapshot.userId() == null) {
            return false;
        }
        Object loginId = ((DigestStpLogic) StpUtil.getStpLogic()).getLoginIdByDigest(digest);
        return loginId != null && snapshot.userId().toString().equals(loginId.toString());
    }

    /**
     * 读取机器主体（服务账号令牌）的权威快照。
     *
     * @param digest 令牌摘要（SHA-256 十六进制）
     * @return 快照根节点，永不为 {@code null}；可用性由 {@code status == ok} 判定
     */
    private JsonNode loadServiceIdentity(String digest) {
        return mapper.readTree(identityMapper.loadServiceIdentity(digest));
    }

    /**
     * 请求形态校验（在进入任何数据库访问之前执行）。
     *
     * <p>规则：请求体与 {@code audience} 必须存在且非空白；
     * {@code subjectToken}（非空白）与 {@code executionContext} 必须<b>恰好其一</b>，
     * 两者同时出现或同时缺失都返回 400——两种模式的判定语义不同，不允许混合语义请求。
     *
     * @param req 待校验请求，可为 {@code null}
     */
    private void validateShape(IntrospectDTO req) {
        if (req == null || req.audience() == null || req.audience().isBlank()) {
            throw ApiException.badRequest("audience 必填");
        }
        boolean hasToken = req.subjectToken() != null && !req.subjectToken().isBlank();
        boolean hasRef = req.executionContext() != null;
        if (hasToken == hasRef) {
            throw ApiException.badRequest("subject_token 与 execution_context 必须且只能提供其一");
        }
    }

    /**
     * 解析引用行中登记的修订快照（jsonb 文本，键为 SNAKE_CASE）。
     *
     * <p>结构与写入侧 {@link #createExecutionContext} 对称；解析失败说明库内数据或
     * 序列化配置异常，此时无法安全判定一致性，按依赖故障 503 失败关闭而非放行。
     *
     * @param json 引用行的 {@code revisions} 文本；{@code null} 或非法 JSON 进入异常分支
     * @return 四项修订（数值组件为 {@code null} 时读为 0，与数据库 {@code COALESCE} 口径一致）
     * @throws ApiException 503 当文本无法解析为预期结构
     */
    private RevisionsDTO parseRevisions(String json) {
        try {
            JsonNode node = mapper.readTree(json);
            return new RevisionsDTO(
                    node.path("user_auth_revision").asLong(),
                    node.path("tenant_auth_revision").asLong(),
                    node.path("membership_revision").asLong(),
                    node.path("session_ctx_version").asLong());
        } catch (Exception e) {
            throw ApiException.dependencyUnavailable("引用修订解析失败");
        }
    }

    /**
     * 把 JSON 数组节点逐项取文本收集为列表。
     *
     * @param array 数组节点；{@code null}、缺失或非数组时按空处理，不抛异常
     * @return 新构造的可变列表，顺序与数组顺序一致；无元素时为空列表
     */
    private static List<String> textList(JsonNode array) {
        List<String> values = new ArrayList<>();
        if (array != null && array.isArray()) {
            array.forEach(n -> values.add(n.asText()));
        }
        return values;
    }

    /**
     * 把可空的期望代次折叠为不可能与会话实际代次相等的最小值。
     *
     * <p>用于 {@code expected_context} 比较：调用方未给出 {@code ctx_version} 时不能当作
     * "跳过比较"，否则等于允许缺字段的请求绕过纪元检查。
     *
     * @param value 期望的上下文代次，可为 {@code null}
     * @return 原值；{@code null} 时返回 {@link Long#MIN_VALUE}
     */
    private static long safeLong(Long value) {
        return value == null ? Long.MIN_VALUE : value;
    }

    /**
     * 解析调用方提交的 UUID 文本。
     *
     * @param value 待解析文本，可为 {@code null}（按非法处理）
     * @param field 出错消息中引用的字段名（对外字段路径，如 {@code expected_context.tenant_id}）
     * @return 解析出的 UUID
     * @throws ApiException 400 当文本不是合法 UUID 字面量或为 {@code null}
     */
    private UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest(field + " 不是合法 UUID");
        }
    }

    /**
     * 构造 {@code active:false} 的内省信封（HTTP 仍为 200，身份详情一律不带出）。
     *
     * <p>reason 映射口径：权威快照的已知停用类状态原样透出，供消费方映射 403——
     * {@code account_disabled}（账号或服务账号停用）、{@code tenant_suspended}（企业停用）、
     * {@code membership_disabled}（成员关系停用）；{@code context_required} 为契约保留值，
     * 当前 {@code load_authority_snapshot} 与 {@code load_service_identity} 都不会产生该状态。
     * 其余取值（含 {@code invalid_or_revoked}、{@code missing} 与任何未预期字符串）一律归一为
     * {@code invalid_or_revoked}，避免把"令牌不存在"与"令牌已撤销"区分开供探测。
     *
     * @param reason 权威快照给出的状态原文；{@code null} 或空串按未知处理，落到
     *               {@code invalid_or_revoked}
     * @return inactive 视图（{@code schemaVersion} 为 {@code iam.introspection.v1}）
     */
    static InactiveIntrospectionVO inactive(String reason) {
        String mapped = switch (reason == null ? "" : reason) {
            case "account_disabled" -> "account_disabled";
            case "tenant_suspended" -> "tenant_suspended";
            case "membership_disabled" -> "membership_disabled";
            case "context_required" -> "context_required";
            default -> "invalid_or_revoked";
        };
        return new InactiveIntrospectionVO(INTROSPECTION_SCHEMA, false, mapped, evaluatedAt());
    }

    /**
     * 取服务端评估时刻的 UTC 文本，写入响应的 {@code evaluated_at}。
     *
     * @return ISO-8601 带偏移时间文本（{@code ZoneOffset.UTC}，形如 {@code 2026-10-16T02:11:00Z}）
     */
    static String evaluatedAt() {
        return OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
}
