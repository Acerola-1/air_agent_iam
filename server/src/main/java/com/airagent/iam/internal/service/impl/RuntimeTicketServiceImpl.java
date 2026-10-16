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
 * {@link RuntimeTicketService} 实现：rt-v1 运行票据签发。
 *
 * <p>分层位置：Service 层，主体有效性完全复用 {@link IntrospectionService#loadHumanSnapshot(String)}
 * （PG 权威快照 + Redis 存活双检），本类不引入第二权威、不自行判断会话是否可用；
 * 签名交给无状态的 {@link RtV1Codec}，审计经 {@link AdminEventMapper} 在独立事务内写入。
 *
 * <p>票据语义：一张严格限定 {@code langgraph-runtime} 受众的短入口凭据，有效期取
 * 配置 TTL（钳制在 1..60 秒）与"会话 idle/绝对到期的最早上界"的较小值。签票不延长会话，
 * 票据到期也不代表会话失效——原会话仍有效时可重新核验再签。
 *
 * <p>失败关闭：受众/必填项不合法 400，主体或凭据无效 401，企业上下文不可用 403，
 * 目标企业与上下文代次不符 409，签名密钥缺失或依赖故障 503；审计写入失败整体回滚，
 * 绝不返回"已签出但无审计"的票据。
 *
 * <p>秘密边界：票据原文与签名密钥都不进入审计、日志与响应以外的任何通道；审计 detail 只记
 * 受众、目标企业与 TTL 秒数。原始 {@code subject_token} 只在本方法内存活，仅取其
 * SHA-256 摘要查库。
 *
 * @author Acerola
 */
@Service
public class RuntimeTicketServiceImpl implements RuntimeTicketService {

    /** 事务内写入 PostgreSQL 请求上下文（RLS 用），使审计行落在正确企业可见域。 */
    private final RequestContextMapper requestContextMapper;
    /** 审计事件写入（与业务变更同事务，失败整体回滚）。 */
    private final AdminEventMapper eventMapper;
    /** 编程式事务边界：仅包裹审计写入。 */
    private final TransactionTemplate tx;
    /** 人类主体实时核验入口（PG 权威 + Redis 存活）。 */
    private final IntrospectionService introspection;
    /** {@code iam.*} 配置：签票 TTL（秒）与 rt-v1 当前密钥 {@code kid}/secret。 */
    private final IamProperties props;
    /** Jackson 实例：审计 detail 序列化（全局 SNAKE_CASE 策略）。 */
    private final ObjectMapper mapper;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param requestContextMapper 请求上下文写入组件
     * @param eventMapper          审计事件写入组件
     * @param tx                   编程式事务边界（本类不使用声明式 {@code @Transactional}）
     * @param introspection        主体实时核验服务
     * @param props                配置属性（{@code iam.internal.*}、{@code iam.rt.*}）
     * @param mapper               JSON 序列化组件
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>实现顺序（每一步都是失败关闭的前置门槛）：
     * <ol>
     *   <li>入参与受众校验：{@code audience} 必须恰为
     *       {@link IntrospectionService#RUNTIME_AUDIENCE}，客户端必须已注册该受众；</li>
     *   <li>密钥就绪校验：{@code iam.rt.kid} 或 {@code iam.rt.secret} 缺失即 503，
     *       不签"无密钥可用"的降级票；</li>
     *   <li>主体实时核验（含 Redis 存活），并按快照状态给出协议语义：不存在/已撤销/已过期与
     *       账号停用为 401，企业与成员关系不可用为 403；机器令牌在此步必然是 401；</li>
     *   <li>上下文一致性：会话必须已选企业，且企业 id 与上下文代次同时等于请求值，否则 409；
     *       成员关系节点缺失为 403；</li>
     *   <li>有效期取小后签名（见 {@link #earliestSessionBound}），剩余不足即 403；</li>
     *   <li>事务内以租户线上下文（{@code app.is_platform = off}）写审计
     *       {@code auth.runtime_ticket_issue}，对象类型 {@code auth_session}、对象 id 为会话 UUID。</li>
     * </ol>
     *
     * <p>票据正文（rt-v1 的 {@code p} 段）固定 12 个字段：
     * {@code typ=rt-v1}、{@code sid}=会话、{@code uid}=用户、{@code tid}=当前企业、
     * {@code mid}=成员关系、{@code aud}=langgraph-runtime、{@code iat}/{@code exp} 为
     * Unix 秒（UTC 纪元秒）、{@code crev}=会话上下文代次、{@code urev}=用户授权代次、
     * {@code trev}=企业授权代次、{@code mrev}=成员关系代次。消费方据此三项修订与
     * {@code crev} 判旧，但票据本身不是授权快照。
     */
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

    /**
     * 取会话三个到期字段的最早上界（Unix 秒），用于把票据有效期压到不超过原会话。
     *
     * <p>依次取 {@code session.absolute_expires_at}、{@code session.idle_expires_at}、
     * {@code session.expires_at} 中可解析项的最小值（ISO-8601 带偏移文本，按 UTC 纪元秒比较）。
     * 三者都缺失或都无法解析时返回"约一年后"的哨兵上界——此时票据事实上只受 60 秒
     * TTL 钳制，绝不因此把有效期放宽到超过 TTL。
     *
     * @param snapshot 已判为可用的权威快照
     * @return 票据到期时刻的上界（Unix 秒，UTC 纪元）
     */
    private long earliestSessionBound(AuthoritySnapshot snapshot) {
        JsonNode session = snapshot.raw().path("session");
        long bound = Long.MAX_VALUE;
        bound = minEpoch(bound, session.path("absolute_expires_at").asText(null));
        bound = minEpoch(bound, session.path("idle_expires_at").asText(null));
        bound = minEpoch(bound, session.path("expires_at").asText(null));
        return bound == Long.MAX_VALUE ? Instant.now().getEpochSecond() + 365 * 24 * 3600L : bound;
    }

    /**
     * 用候选 ISO-8601 时间文本收窄上界。
     *
     * @param current 当前已知上界（Unix 秒）
     * @param iso     待比较的时间文本；{@code null}、空白或无法解析时视为"该维度不构成上界"
     * @return 两者的较小值；无法解析时原样返回 {@code current}（不因脏数据放宽有效期）
     */
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
