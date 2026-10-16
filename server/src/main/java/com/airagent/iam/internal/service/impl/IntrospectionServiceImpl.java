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
 * 内部 introspection 用例：普通 token 模式（人类/服务账号）与 verification_ref 复查模式。
 *
 * <p>每次调用读 PG 主库；人类主体同时检查 Redis 会话存活，不缓存跨请求授权结果。
 */
@Service
public class IntrospectionServiceImpl implements IntrospectionService {

    private final IdentityMapper identityMapper;
    private final SessionMapper sessionMapper;
    private final TransactionTemplate tx;
    private final IdentityAssembler assembler;
    private final IamProperties props;
    private final ObjectMapper mapper;

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

    private record ReferenceEvaluationBO(RecheckActiveVO active, RecheckInactiveVO inactive,
                                           AuthoritySnapshot snapshot, String digest) {
        private static ReferenceEvaluationBO rejected(String reason) {
            return new ReferenceEvaluationBO(null,
                    new RecheckInactiveVO(false, false, reason, evaluatedAt()), null, null);
        }
    }

    private RevisionsDTO currentRevisions(AuthoritySnapshot snapshot) {
        JsonNode rev = snapshot.raw().path("revisions");
        return new RevisionsDTO(
                rev.path("user_auth_revision").asLong(),
                rev.path("tenant_auth_revision").asLong(),
                rev.path("membership_revision").asLong(),
                rev.path("session_ctx_version").asLong());
    }

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

    @Override
    public AuthoritySnapshot loadHumanSnapshot(String digest) {
        AuthoritySnapshot snapshot = AuthoritySnapshot.of(mapper.readTree(sessionMapper.loadSnapshotJson(digest)));
        if (snapshot.usable() && !redisSessionMatches(digest, snapshot)) {
            return new AuthoritySnapshot("invalid_or_revoked", snapshot.raw());
        }
        return snapshot;
    }

    private boolean redisSessionMatches(String digest, AuthoritySnapshot snapshot) {
        if (digest == null || snapshot.userId() == null) {
            return false;
        }
        Object loginId = ((DigestStpLogic) StpUtil.getStpLogic()).getLoginIdByDigest(digest);
        return loginId != null && snapshot.userId().toString().equals(loginId.toString());
    }

    private JsonNode loadServiceIdentity(String digest) {
        return mapper.readTree(identityMapper.loadServiceIdentity(digest));
    }

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

    private static List<String> textList(JsonNode array) {
        List<String> values = new ArrayList<>();
        if (array != null && array.isArray()) {
            array.forEach(n -> values.add(n.asText()));
        }
        return values;
    }

    private static long safeLong(Long value) {
        return value == null ? Long.MIN_VALUE : value;
    }

    private UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest(field + " 不是合法 UUID");
        }
    }

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

    static String evaluatedAt() {
        return OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }
}
