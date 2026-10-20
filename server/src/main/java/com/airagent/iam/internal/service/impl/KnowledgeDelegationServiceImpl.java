package com.airagent.iam.internal.service.impl;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.internal.dto.KnowledgeDelegationDTO;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.internal.dto.RevisionsDTO;
import com.airagent.iam.internal.entity.IssuedKnowledgeDelegationDO;
import com.airagent.iam.internal.mapper.IdentityMapper;
import com.airagent.iam.internal.service.KnowledgeDelegationService;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.vo.RecheckActiveVO;
import com.airagent.iam.internal.vo.KnowledgeDelegationVO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * {@link KnowledgeDelegationService} 实现。
 *
 * <p>判定全部在数据库函数 {@code iam_auth.create_knowledge_delegation} 内完成；本类只做
 * 协议形态校验、随机令牌生成与响应装配。原始令牌只在响应体中出现一次，本类不记录日志。
 */
@Service
public class KnowledgeDelegationServiceImpl implements KnowledgeDelegationService {

    private static final String REQUEST_SCHEMA = "iam.knowledge-delegation-request.v1";
    private static final String RESPONSE_SCHEMA = "iam.knowledge-delegation.v1";
    private static final Set<String> OPERATIONS =
            Set.of("query", "record:read", "source:read", "document:read");

    private final IdentityMapper identityMapper;
    private final IamProperties props;
    private final ObjectMapper mapper;
    private final IntrospectionService introspectionService;

    /**
     * 构造实现。
     *
     * @param identityMapper 委托持久化函数入口
     * @param props          {@code iam.internal.*} 配置（TTL）
     * @param mapper         JSON 解析
     */
    public KnowledgeDelegationServiceImpl(IdentityMapper identityMapper, IamProperties props,
                                          ObjectMapper mapper, IntrospectionService introspectionService) {
        this.identityMapper = identityMapper;
        this.props = props;
        this.mapper = mapper;
        this.introspectionService = introspectionService;
    }

    @Override
    public KnowledgeDelegationVO issue(InternalClient client, KnowledgeDelegationDTO req) {
        if (req == null || !REQUEST_SCHEMA.equals(req.schemaVersion())) {
            throw ApiException.badRequest("schema_version 必须为 " + REQUEST_SCHEMA);
        }
        if (!client.hasAudience(AUDIENCE)) {
            throw ApiException.forbidden("客户端未注册 knowledge 受众");
        }
        if (req.operation() == null || !OPERATIONS.contains(req.operation())) {
            throw ApiException.badRequest("operation 不是受支持的只读操作");
        }
        if (req.executionContext() == null
                || req.executionContext().verificationRef() == null
                || req.executionContext().verificationRef().isBlank()
                || req.executionContext().expectedRevisions() == null) {
            throw ApiException.badRequest("execution_context.verification_ref 与 expected_revisions 必填");
        }
        RevisionsDTO expected = req.executionContext().expectedRevisions();
        if (expected.userAuthRevision() == null || expected.tenantAuthRevision() == null
                || expected.membershipRevision() == null || expected.sessionCtxVersion() == null) {
            throw ApiException.badRequest("expected_revisions 四项修订必填");
        }
        UUID referenceId;
        UUID requestedTenant;
        try {
            referenceId = UUID.fromString(req.executionContext().verificationRef());
            requestedTenant = UUID.fromString(req.sourceTenantId());
        } catch (NullPointerException | IllegalArgumentException e) {
            throw ApiException.badRequest("verification_ref 或 source_tenant_id 不是合法 UUID");
        }
        long ttl = props.internal().knowledgeDelegationTtlSeconds();
        if (ttl < 1 || ttl > 60) {
            throw ApiException.dependencyUnavailable("知识委托 TTL 配置超出 1..60 秒");
        }

        // Reuse the existing PG + Redis live-session check before persisting a
        // delegation. A PG-active row alone must not authorize issuance.
        Object source = introspectionService.introspect(client,
                new IntrospectDTO(null, req.executionContext(), "langgraph-runtime", null, false));
        if (!(source instanceof RecheckActiveVO active) || !active.active() || !active.contextMatches()) {
            throw ApiException.unauthenticated("源引用或会话不可用");
        }

        String token = TOKEN_PREFIX + OpaqueTokens.newRawToken();
        String digest = OpaqueTokens.digest(token);
        IssuedKnowledgeDelegationDO issued;
        try {
            issued = identityMapper.createKnowledgeDelegation(
                    client.clientId(), referenceId, req.operation(), digest, ttl);
        } catch (org.springframework.dao.DataAccessException e) {
            throw translate(e);
        }
        if (issued == null) {
            throw ApiException.unauthenticated("执行引用不可用");
        }
        if (!requestedTenant.equals(issued.tenantId())) {
            throw ApiException.contextChanged("source_tenant_id 与源会话当前企业不一致");
        }
        JsonNode revisions;
        try {
            revisions = mapper.readTree(issued.revisionsJson());
        } catch (Exception e) {
            throw ApiException.dependencyUnavailable("委托修订解析失败");
        }
        RevisionsDTO actual = new RevisionsDTO(
                revisions.path("user_auth_revision").asLong(),
                revisions.path("tenant_auth_revision").asLong(),
                revisions.path("membership_revision").asLong(),
                revisions.path("session_ctx_version").asLong());
        if (!expected.equals(actual)) {
            throw ApiException.contextChanged("expected_revisions 与源会话当前修订不一致");
        }
        return new KnowledgeDelegationVO(
                RESPONSE_SCHEMA,
                token,
                "Bearer",
                AUDIENCE,
                req.operation(),
                issued.expiresAt().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                new KnowledgeDelegationVO.Source(
                        issued.userId().toString(),
                        issued.sessionId().toString(),
                        issued.tenantId().toString(),
                        issued.membershipId().toString(),
                        issued.contextVersion(),
                        actual));
    }

    /**
     * 把数据库拒绝映射为协议语义；不泄露源用户或权限细节。
     *
     * @param e 数据访问异常
     * @return 待抛出的 API 异常
     */
    private ApiException translate(org.springframework.dao.DataAccessException e) {
        String state = com.airagent.iam.web.error.PgErrorTranslator.deepest(e) == null
                ? null
                : com.airagent.iam.web.error.PgErrorTranslator.deepest(e).getSQLState();
        if ("28000".equals(state)) {
            return ApiException.unauthenticated("源引用或会话不可用");
        }
        if ("42501".equals(state)) {
            return ApiException.forbidden("当前企业没有有效知识库读取权限");
        }
        if ("22023".equals(state)) {
            return ApiException.badRequest("知识委托参数不合法");
        }
        return com.airagent.iam.web.error.PgErrorTranslator.toApiException(e);
    }
}
