package com.airagent.iam.internal.service.impl;

import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.service.RuntimeTicketService;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.security.rt.RtV1Body;
import com.airagent.iam.security.rt.RtV1Codec;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * rt-v1 运行票据签发：PG 权威实时核验后签发 ≤60s 短入口票据，受会话有效期再取小。
 * 票据本身不入审计/日志；target/ctx 不符 409，未选企业或停用 403。
 */
@Service
public class RuntimeTicketServiceImpl implements RuntimeTicketService {

    private final RequestContextMapper requestContextMapper;
    private final AdminEventMapper eventMapper;
    private final TransactionTemplate tx;
    private final IntrospectionService introspection;
    private final IamProperties props;
    private final ObjectMapper mapper;

    public RuntimeTicketServiceImpl(RequestContextMapper requestContextMapper, AdminEventMapper eventMapper, TransactionTemplate tx,
                                IntrospectionService introspection, IamProperties props,
                                ObjectMapper mapper) {
        this.requestContextMapper = requestContextMapper;
        this.eventMapper = eventMapper;
        this.tx = tx;
        this.introspection = introspection;
        this.props = props;
        this.mapper = mapper;
    }

    @Override
    public RuntimeTicketVO issue(InternalClient client, RuntimeTicketDTO req) {
        if (req == null || req.subjectToken() == null || req.subjectToken().isBlank()) {
            throw ApiException.badRequest("subject_token 必填");
        }
        if (!IntrospectionService.RUNTIME_AUDIENCE.equals(req.audience())) {
            throw ApiException.badRequest("audience 必须为 langgraph-runtime");
        }
        if (!client.hasAudience(IntrospectionService.RUNTIME_AUDIENCE)) {
            throw ApiException.forbidden("客户端未注册 langgraph-runtime 受众");
        }
        if (req.targetTenantId() == null || req.expectedCtxVersion() == null) {
            throw ApiException.badRequest("target_tenant_id 与 expected_ctx_version 必填");
        }
        UUID targetTenant;
        try {
            targetTenant = UUID.fromString(req.targetTenantId());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("target_tenant_id 不是合法 UUID");
        }
        IamProperties.Rt rt = props.rt();
        if (rt == null || rt.kid() == null || rt.kid().isBlank()
                || rt.secret() == null || rt.secret().isBlank()) {
            throw ApiException.dependencyUnavailable("运行票据签名密钥未配置");
        }

        AuthoritySnapshot snapshot = introspection.loadHumanSnapshot(OpaqueTokens.digest(req.subjectToken()));
        if (!snapshot.usable()) {
            // 机器令牌不允许换运行票（无会话/无企业上下文）
            throw switch (snapshot.status()) {
                case "missing", "invalid_or_revoked" ->
                        ApiException.unauthenticated("会话无效或已被撤销");
                case "account_disabled" -> ApiException.unauthenticated("账号已停用");
                case "tenant_suspended", "membership_disabled" ->
                        ApiException.forbidden("企业上下文不可用");
                default -> ApiException.unauthenticated("会话不可用");
            };
        }
        UUID currentTenant = snapshot.currentTenantId();
        if (currentTenant == null) {
            throw ApiException.forbidden("会话尚未选择企业上下文");
        }
        if (!currentTenant.equals(targetTenant) || snapshot.ctxVersion() != req.expectedCtxVersion()) {
            throw ApiException.contextChanged("target_tenant_id/ctx 与当前会话不一致");
        }
        JsonNode memberNode = snapshot.raw().path("membership");
        if (memberNode.isMissingNode() || memberNode.isNull()) {
            throw ApiException.forbidden("企业成员关系不存在");
        }
        UUID membershipId = UUID.fromString(memberNode.path("id").asText());

        Instant now = Instant.now();
        long iat = now.getEpochSecond();
        long requestedExp = iat + Math.min(60, Math.max(1, props.internal().ticketTtlSeconds()));
        long cappedExp = Math.min(requestedExp, earliestSessionBound(snapshot));
        if (cappedExp <= iat) {
            throw ApiException.forbidden("会话剩余有效期不足");
        }

        JsonNode rev = snapshot.raw().path("revisions");
        RtV1Body body = new RtV1Body(
                snapshot.sessionId(),
                snapshot.userId(),
                currentTenant,
                membershipId,
                IntrospectionService.RUNTIME_AUDIENCE,
                iat,
                cappedExp,
                snapshot.ctxVersion(),
                rev.path("user_auth_revision").asLong(),
                rev.path("tenant_auth_revision").asLong(),
                rev.path("membership_revision").asLong());
        String ticket = RtV1Codec.sign(body, rt.kid(), rt.secret().getBytes(StandardCharsets.UTF_8));

        tx.executeWithoutResult(status -> {
            requestContextMapper.setContext(snapshot.userId(), currentTenant, false);
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("audience", IntrospectionService.RUNTIME_AUDIENCE);
            detail.put("target_tenant_id", targetTenant.toString());
            detail.put("ttl_seconds", cappedExp - iat);
            try {
                eventMapper.insertAudit(currentTenant, snapshot.userId(), "auth.runtime_ticket_issue",
                        "auth_session", snapshot.sessionId().toString(), mapper.writeValueAsString(detail),
                        MDC.get("request_id"));
            } catch (com.airagent.iam.web.error.ApiException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("审计写入失败（事务必须整体回滚）", e);
            }
        });

        return new RuntimeTicketVO(
                ticket,
                "Bearer",
                OffsetDateTime.ofInstant(Instant.ofEpochSecond(cappedExp), ZoneOffset.UTC)
                        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                cappedExp - iat,
                IntrospectionService.RUNTIME_AUDIENCE,
                RtV1Codec.FORMAT);
    }

    /** 取会话 idle/absolute 到期的最早上界（秒）；缺失则只受 60s TTL 约束。 */
    private long earliestSessionBound(AuthoritySnapshot snapshot) {
        JsonNode session = snapshot.raw().path("session");
        long bound = Long.MAX_VALUE;
        bound = minEpoch(bound, session.path("absolute_expires_at").asText(null));
        bound = minEpoch(bound, session.path("idle_expires_at").asText(null));
        bound = minEpoch(bound, session.path("expires_at").asText(null));
        return bound == Long.MAX_VALUE ? Instant.now().getEpochSecond() + 365 * 24 * 3600L : bound;
    }

    private static long minEpoch(long current, String iso) {
        if (iso == null || iso.isBlank()) {
            return current;
        }
        try {
            return Math.min(current, OffsetDateTime.parse(iso).toEpochSecond());
        } catch (RuntimeException e) {
            return current;
        }
    }
}
