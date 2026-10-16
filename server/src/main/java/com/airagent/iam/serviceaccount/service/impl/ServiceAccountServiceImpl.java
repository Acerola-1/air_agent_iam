package com.airagent.iam.serviceaccount.service.impl;

import com.airagent.iam.admin.entity.TenantDO;
import com.airagent.iam.admin.mapper.TenantMapper;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.dto.UpdateServiceAccountDTO;
import com.airagent.iam.serviceaccount.entity.IssuedTokenDO;
import com.airagent.iam.serviceaccount.entity.ServiceAccountDO;
import com.airagent.iam.serviceaccount.mapper.ServiceAccountMapper;
import com.airagent.iam.serviceaccount.service.ServiceAccountService;
import com.airagent.iam.serviceaccount.vo.ServiceAccountDetailVO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenVO;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * {@link ServiceAccountService} 实现：服务账号与凭据生命周期（权限码 {@code platform:service:write}）。
 *
 * <p>分层与协作：Controller 只透传，本类负责权限裁决、入参格式判定、事务编排、审计装配与
 * DO→VO 转换；数据访问集中在 {@link ServiceAccountMapper}，其中凭据表的一切读写都经
 * iam_auth 下的受控函数（{@code issue_service_token} / {@code revoke_service_token} /
 * {@code list_service_tokens}），因为 {@code iam.service_tokens} 对请求角色默认拒绝直读。
 * 每个操作都在 {@code TransactionTemplate} 内以第一步设置平台请求上下文
 * （{@code app.is_platform=on}、租户为空）开始，行可见性交由 RLS 裁决；数据库错误经
 * {@link PgErrorTranslator} 翻译为协议语义。审计与业务变更同事务，写失败整体回滚。
 *
 * <p>凭据边界：明文密钥在本类中只存活于 {@link #issueToken} 的一次调用内——先随机生成，
 * 立即以 SHA-256 十六进制摘要作为入参写库，响应体返回明文，服务端不留副本、日志与审计
 * detail 也不含它（审计只记凭据标识与时间）。因此凭据不可再次读取，丢失只能重新签发。
 *
 * <p>时间约束（单位均为应用侧常量 + 数据库约束共同决定）：账号有效期缺省 90 天、硬顶 365 天；
 * 凭据有效期固定 90 天且被账号到期截断；轮换重叠窗口上限 24 小时。无永久凭据、不自动续期。
 *
 * <p>轮换语义（以 SQL 为准，见 V14 与 V19）：签发新凭据时，重叠窗口写在
 * <b>该账号当时全部 active 旧凭据</b>上而不是新凭据上（新凭据的 {@code overlap_until} 恒为空）；
 * 窗口为 0 或缺省即“零窗口”，旧凭据当场转为 revoked 并写入 revoked_at；窗口从
 * <b>本次轮换时刻</b>起算（{@code rotated_at}），而非旧凭据的最初签发时刻，上界同时受旧凭据
 * 自身到期时间截断。账号停用不删除凭据，但每次核验都读主库、无正向缓存，故停用与吊销即时生效；
 * 服务凭据不经 Sa-Token/Redis 会话存储，本类不投递 Redis 删除事件。
 *
 * @author Acerola
 */
@Service
public class ServiceAccountServiceImpl implements ServiceAccountService {

    private final com.airagent.iam.admin.ResourceGrantSupport grants;

    /** 服务账号与凭据管理的唯一权限码：本模块所有读写操作（含列表与详情）都要求它。 */
    static final String PERMISSION_SERVICE_WRITE = "platform:service:write";
    /** 账号有效期缺省天数（请求未给 expires_in_days 时），同时也是凭据的固定有效天数。 */
    private static final int DEFAULT_EXPIRES_DAYS = 90;
    /** 账号有效期硬顶天数，与数据库 expires_at 的 CHECK 约束同值。 */
    private static final int MAX_EXPIRES_DAYS = 365;
    /** 轮换重叠窗口上限小时数，与数据库 24 小时约束同值。 */
    private static final int MAX_OVERLAP_HOURS = 24;

    /** 服务账号与凭据数据访问（凭据侧一律走受控函数）。 */
    private final ServiceAccountMapper serviceAccountMapper;
    /** 企业读取：建档时校验目标企业存在且处于 active 状态。 */
    private final TenantMapper tenantMapper;
    /** 事务内写入 PostgreSQL 请求上下文（平台线：租户为空、is_platform 为真）。 */
    private final RequestContextMapper requestContextMapper;
    /** 审计写入与事件投递；本类只用审计插入。 */
    private final AdminEventMapper eventMapper;
    /** 编程式事务边界（本类不使用声明式 @Transactional）。 */
    private final TransactionTemplate tx;
    /** 审计 detail 的 JSON 序列化器。 */
    private final ObjectMapper mapper;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param serviceAccountMapper 服务账号与凭据数据访问
     * @param tenantMapper         企业状态校验
     * @param requestContextMapper 请求上下文写入（RLS 依据）
     * @param eventMapper          审计事件写入
     * @param tx                   事务边界
     * @param mapper               审计 detail 序列化
     */
    public ServiceAccountServiceImpl(ServiceAccountMapper serviceAccountMapper, TenantMapper tenantMapper,
                                     RequestContextMapper requestContextMapper, AdminEventMapper eventMapper, TransactionTemplate tx, ObjectMapper mapper, com.airagent.iam.admin.ResourceGrantSupport grants) {
        this.serviceAccountMapper = serviceAccountMapper;
        this.tenantMapper = tenantMapper;
        this.requestContextMapper = requestContextMapper;
        this.eventMapper = eventMapper;
        this.tx = tx;
        this.mapper = mapper;
        this.grants = grants;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：全部格式判定在开事务之前完成——account 必须匹配
     * {@code sa-[a-z0-9][a-z0-9-]{1,62}[a-z0-9]}，name 非空白且不超过 128 字符，
     * tenant_id 必须可解析为 UUID（解析失败按 400，不区分“不存在”与“格式错”），
     * {@code expires_in_days} 缺省取 90、合法范围 1..365，受众与权限码经同一套消毒规则。
     * 事务内先读企业行确认其为 active（不存在或 suspended 都是 400），再以应用侧 UTC 时刻
     * 加天数算出到期并插入账号，随后逐条写入权限授予。
     * 响应体由请求参数当场拼装（不回读数据库）：status 为 active、revision 为 1，
     * permissions 是消毒后的申请码。审计 service_account.create 不含任何秘密。
     */
    @Override
    public ServiceAccountVO create(CurrentSession actor, CreateServiceAccountDTO req) {
        requireServiceWrite(actor);
        if (req == null) {
            throw ApiException.badRequest("请求体必填");
        }
        if (req.account() == null || !req.account().matches("sa-[a-z0-9][a-z0-9-]{1,62}[a-z0-9]")) {
            throw ApiException.badRequest("account 需为 sa- 前缀的 3-64 位小写字母数字/连字符");
        }
        if (req.name() == null || req.name().isBlank() || req.name().length() > 128) {
            throw ApiException.badRequest("name 不合法");
        }
        UUID tenantId;
        try {
            tenantId = UUID.fromString(req.tenantId());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest("tenant_id 不是合法 UUID");
        }
        List<String> audiences = sanitizeAudiences(req.audiences());
        int days = req.expiresInDays() == null ? DEFAULT_EXPIRES_DAYS : req.expiresInDays();
        if (days < 1 || days > MAX_EXPIRES_DAYS) {
            throw ApiException.badRequest("expires_in_days 必须在 1 到 365 之间");
        }
        List<UUID> permissionIds = resolvePermissionCodes(req.permissions());

        try {
            return tx.execute(status -> {
                setPlatformContext(actor.userId());
                List<String> requested = sanitizeAudiences(req.permissions());
                grants.lockWrite(actor, tenantId, requested, req.expectedContext(), req.expectedTenantRevision());
                for (var permission : grants.permissions(requested)) {
                    if (permission.resourceCode() != null && !grants.resourceAvailable(tenantId, permission)) {
                        throw ApiException.conflict("资源未开通或已停用");
                    }
                }
                TenantDO tenant = tenantMapper.selectTenant(tenantId);
                if (tenant == null || !"active".equals(tenant.status())) {
                    throw ApiException.badRequest("目标企业未处于 active 状态");
                }
                OffsetDateTime expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plusDays(days);
                UUID saId = serviceAccountMapper.insert(req.account(), req.name(), tenantId, audiences,
                        expiresAt, actor.userId());
                for (UUID permissionId : permissionIds) {
                    serviceAccountMapper.insertPermission(tenantId, saId, permissionId, actor.userId());
                }
                List<String> grantedCodes = sanitizeAudiences(req.permissions());
                audit(tenantId, actor.userId(), "service_account.create", "service_account",
                        saId.toString(), Map.of(
                                "account", req.account(),
                                "audiences", audiences,
                                "expires_in_days", days,
                                "permissions", grantedCodes));
                return new ServiceAccountVO(saId.toString(), req.account(), req.name(),
                        tenantId.toString(), "active", audiences, expiresAt.toString(), 1,
                        grantedCodes);
            });
        } catch (DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：入参解析与窗口范围校验在开事务前完成；明文密钥与凭据标识
     * （{@code sak_} + 去连字符的随机 UUID，32 位小写十六进制）在进事务前生成，
     * 摘要则在调用签发函数前即时由 {@link OpaqueTokens#digest(String)} 单向算出。事务内先
     * {@code SELECT ... FOR UPDATE} 锁住账号行（串行化并发签发，不存在即 404），
     * 再按“应用侧 UTC 时刻 + 90 天”算凭据到期并被账号到期时间截断——调用方不能指定凭据期限。
     *
     * <p>重叠窗口由服务侧换算为 {@code 时刻 + overlap_hours - 1 秒}（减 1 秒的理由见方法内注释），
     * 并被新凭据到期时间截断；窗口只作用于旧凭据，新凭据的窗口列恒为空。
     * 因此响应与审计里的 {@code overlap_until} 是“施加于被取代旧凭据的期望上界”，
     * 数据库对每枚旧凭据还会再按其自身到期时间取较小值，个别旧凭据的实际上界可能更早。
     * 审计 service_account.token_issue 记录账号 id、凭据标识与时间，不含明文与摘要；
     * 其 overlap_until 字段取自签发函数回显的新行窗口列（该列恒为空），故总记为空串。
     */
    @Override
    public ServiceTokenIssuedVO issueToken(CurrentSession actor, String serviceAccountId,
                                         CreateServiceTokenDTO req) {
        requireServiceWrite(actor);
        UUID saId;
        try {
            saId = UUID.fromString(serviceAccountId);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("service_account_id 不是合法 UUID");
        }
        Integer overlapHours = req == null ? null : req.overlapHours();
        if (overlapHours != null && (overlapHours < 0 || overlapHours > MAX_OVERLAP_HOURS)) {
            throw ApiException.badRequest("overlap_hours 必须在 0 到 24 之间");
        }

        String rawSecret = OpaqueTokens.newRawToken();
        String credentialId = "sak_" + UUID.randomUUID().toString().replace("-", "");
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        try {
            return tx.execute(status -> {
                setPlatformContext(actor.userId());
                ServiceAccountDO sa = serviceAccountMapper.lockById(saId);
                if (sa == null) {
                    throw ApiException.notFound("服务账号不存在");
                }
                UUID saTenantId = sa.tenantId();
                OffsetDateTime tokenExpiry = now.plusDays(DEFAULT_EXPIRES_DAYS);
                OffsetDateTime cap = sa.expiresAt();
                if (tokenExpiry.isAfter(cap)) {
                    tokenExpiry = cap;
                }
                OffsetDateTime overlap = null;
                if (overlapHours != null && overlapHours > 0) {
                    // 减 1 秒：DB 以 issued_at(≈SQL now) 计 24h 硬上界，避免应用时钟差导致 24h 整点被判越界
                    overlap = now.plusHours(overlapHours).minusSeconds(1);
                    if (overlap.isAfter(tokenExpiry)) {
                        overlap = tokenExpiry;
                    }
                }
                IssuedTokenDO row = serviceAccountMapper.issueToken(saId, credentialId,
                        OpaqueTokens.digest(rawSecret), tokenExpiry, overlap);
                audit(saTenantId, actor.userId(), "service_account.token_issue", "service_token",
                        credentialId, Map.of(
                                "service_account_id", saId.toString(),
                                "credential_id", credentialId,
                                "expires_at", iso(row.expiresAt()),
                                "overlap_until", row.overlapUntil() == null
                                        ? "" : iso(row.overlapUntil())));
                return new ServiceTokenIssuedVO(
                        credentialId,
                        rawSecret,
                        "Bearer",
                        iso(row.expiresAt()),
                        iso(overlap),
                        row.credentialRevision());
            });
        } catch (DataAccessException e) {
            throw PgErrorTranslator.toApiException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：标识必须先匹配 {@code sak_[a-f0-9]{32}} 才进入事务（格式不符 400，
     * 不做前缀之外的额外校验）。事务内只调用吊销函数并写审计：函数只更新状态为 active 的行，
     * 对不存在或已 revoked 的标识不做变更且不报错，故本方法同样不抛 404——
     * 幂等重复调用与吊销未知标识都会留下一条 service_account.token_revoke 审计。
     * 服务凭据不写入 Redis 会话存储，因此这里没有会话键删除或 outbox 投递。
     */
    @Override
    public void revokeToken(CurrentSession actor, String credentialId) {
        requireServiceWrite(actor);
        if (credentialId == null || !credentialId.matches("sak_[a-f0-9]{32}")) {
            throw ApiException.badRequest("credential_id 不合法");
        }
        tx.executeWithoutResult(status -> {
            setPlatformContext(actor.userId());
            // 撤销幂等；审计记录操作者与凭据标识（非秘密）
            serviceAccountMapper.revokeToken(credentialId);
            audit(null, actor.userId(), "service_account.token_revoke", "service_token",
                    credentialId, Map.of("credential_id", credentialId));
        });
    }

    // ---------------------------------------------------------------- 列表/详情/停用

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：limit 与 cursor 先于事务解析（多取一行探测 {@code hasMore}，
     * 仅当确有下一页且本页非空时才生成 {@code nextCursor}，游标内容是本页末行的账号 UUID 文本
     * 的 base64url 无填充编码）。租户过滤值不校验企业是否存在，未知企业得到空页；
     * 每行的权限码逐行查询装配（行数受 limit 上限约束）。
     */
    @Override
    public PageVO<ServiceAccountVO> list(CurrentSession actor, String tenantIdRaw,
                                         Integer limitRaw, String cursorRaw) {
        requireServiceWrite(actor);
        int limit = clampLimit(limitRaw);
        String cursor = decodeCursor(cursorRaw);
        final UUID tenantFilter;
        if (tenantIdRaw != null && !tenantIdRaw.isBlank()) {
            try {
                tenantFilter = UUID.fromString(tenantIdRaw);
            } catch (IllegalArgumentException e) {
                throw ApiException.badRequest("tenant_id 不是合法 UUID");
            }
        } else {
            tenantFilter = null;
        }
        return tx.execute(status -> {
            setPlatformContext(actor.userId());
            UUID afterId = cursor == null ? null : UUID.fromString(cursor);
            List<ServiceAccountDO> rows = serviceAccountMapper.selectPage(tenantFilter, afterId, limit + 1);
            boolean hasMore = rows.size() > limit;
            List<ServiceAccountVO> items = rows.stream().limit(limit).map(this::toView).toList();
            String next = hasMore && !items.isEmpty()
                    ? encodeCursor(items.get(items.size() - 1).id()) : null;
            return new PageVO<>(items, next);
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：账号部分由 {@link #loadView} 装配（不存在或不可见 404）；凭据部分经
     * 受控函数读取元数据后逐行转 VO，时间统一经 {@link #iso} 归一为 UTC ISO-8601 文本，
     * {@code overlapUntil} 与 {@code revokedAt} 未发生时为 {@code null}。从未签发时
     * {@code tokens} 为空列表，本方法不因“无凭据”而报错。
     */
    @Override
    public ServiceAccountDetailVO get(CurrentSession actor, String idRaw) {
        requireServiceWrite(actor);
        UUID saId = parseSaId(idRaw);
        return tx.execute(status -> {
            setPlatformContext(actor.userId());
            ServiceAccountVO view = loadView(saId);
            // service_tokens 对 iam_app 默认拒绝直读（ENABLE RLS 无 policy），经受控函数取元数据
            List<ServiceTokenVO> tokens = serviceAccountMapper.selectTokens(saId).stream()
                    .map(row -> new ServiceTokenVO(row.credentialId(), row.credentialRevision(), row.status(),
                            iso(row.issuedAt()), iso(row.expiresAt()), iso(row.overlapUntil()), iso(row.revokedAt())))
                    .toList();
            return new ServiceAccountDetailVO(view, tokens);
        });
    }

    /**
     * 停用/重新启用服务账号。
     *
     * <p>停用即时生效：机器身份的每次核验（introspection）都读主库判定账号状态，
     * 无正向授权缓存，因此停用后既有凭据下一跳即返回 {@code account_disabled}；
     * 本方法不删除、也不改写任何凭据行（永久撤销凭据请逐个吊销）。
     * 账号 {@code revision} 在每条 UPDATE 里无条件 +1，供审计与消费者识别——
     * 它不是并发基线：本方法既不读取也不比较原 revision，重复提交同一状态同样推进它。
     *
     * <p>实现细节：状态取值先校验（只接受 active/disabled），事务内以影响行数判定存在性，
     * {@code updated == 0} 视为不存在或 RLS 不可见并抛 404；成功后回读装配视图返回。
     *
     * @param actor 当前会话快照；须持有 {@code platform:service:write}，为 {@code null} 按 403 处理
     * @param idRaw 服务账号 UUID 文本；{@code null} 或不可解析时 400
     * @param req   状态请求；{@code null}、{@code status} 为空或取值非 active/disabled 时 400
     * @return 变更后的账号视图（{@code revision} 较调用前 +1）
     * @throws com.airagent.iam.web.error.ApiException 400 参数不合法；403 缺少权限；
     *         404 账号不存在或不可见
     */
    @Override
    public ServiceAccountVO updateStatus(CurrentSession actor, String idRaw,
                                           UpdateServiceAccountDTO req) {
        requireServiceWrite(actor);
        UUID saId = parseSaId(idRaw);
        if (req == null || req.status() == null
                || (!req.status().equals("active") && !req.status().equals("disabled"))) {
            throw ApiException.badRequest("status 仅支持 active/disabled（永久撤销请逐个吊销凭据）");
        }
        return tx.execute(status -> {
            setPlatformContext(actor.userId());
            int updated = serviceAccountMapper.updateStatus(saId, req.status());
            if (updated == 0) {
                throw ApiException.notFound("服务账号不存在");
            }
            audit(null, actor.userId(), "service_account.status_update", "service_account",
                    saId.toString(), Map.of("status", req.status()));
            return loadView(saId);
        });
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * 解析路径中的服务账号标识。
     *
     * <p>{@link UUID#fromString(String)} 对 {@code null} 抛 {@link NullPointerException}、
     * 对非法文本抛 {@link IllegalArgumentException}，两者一律收敛为同一个 400，
     * 不向调用方区分“缺失”与“格式错”。
     *
     * @param raw 路径变量原文（期望为 UUID 文本）；可为 {@code null}
     * @return 解析后的账号 UUID
     * @throws com.airagent.iam.web.error.ApiException 400 当文本为空或不是合法 UUID
     */
    private static UUID parseSaId(String raw) {
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest("service_account_id 不是合法 UUID");
        }
    }

    /**
     * 归一并校验单页条数。
     *
     * @param limit 请求传入的条数；{@code null} 表示未指定，取默认 20
     * @return 实际生效的条数，范围为 1..200
     * @throws com.airagent.iam.web.error.ApiException 400 当值小于 1 或大于 200
     */
    private static int clampLimit(Integer limit) {
        if (limit == null) {
            return 20;
        }
        if (limit < 1 || limit > 200) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        return limit;
    }

    /**
     * 把本页末行 id 编码为不透明游标。
     *
     * <p>内容只是上一页末行的账号 UUID 文本经 base64url 无填充编码，不含秘密；
     * 但调用方应视其为不透明串、原样回传，不要自行构造或解析。
     *
     * @param lastId 本页最后一行的账号 UUID 文本，不可为 {@code null}
     * @return 游标字符串（无 {@code =} 填充位）
     */
    private static String encodeCursor(String lastId) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(lastId.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 解码并校验游标。
     *
     * <p>解码结果必须能再被解析为 UUID，因此非法 base64、被篡改内容或越权构造的
     * 非 UUID 文本一律 400；成功时返回 UUID 的规范文本（后续再解析为 UUID 不会失败）。
     *
     * @param cursor 请求携带的游标原文；{@code null} 或空白表示从首页开始
     * @return 首页时 {@code null}，否则为规范化后的 UUID 文本
     * @throws com.airagent.iam.web.error.ApiException 400 当游标无法解码为 UUID
     */
    private static String decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            return UUID.fromString(decoded).toString();
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("cursor 不合法");
        }
    }

    /**
     * 读取并装配单个账号视图（详情页与状态变更后的回读共用）。
     *
     * <p>须在已设置请求上下文的事务内调用，否则 RLS 会让读取结果为空。
     *
     * @param saId 服务账号 UUID
     * @return 账号视图（含已授予权限码）
     * @throws com.airagent.iam.web.error.ApiException 404 当行不存在或 RLS 不可见
     */
    private ServiceAccountVO loadView(UUID saId) {
        ServiceAccountDO account = serviceAccountMapper.selectById(saId);
        if (account == null) {
            throw ApiException.notFound("服务账号不存在");
        }
        return toView(account);
    }

    /**
     * DO 到账号视图的转换：追加一次权限码查询，到期时间归一为 UTC ISO-8601 文本。
     *
     * <p>分页列表按行调用本方法，因此每行都会额外发一条权限码查询（行数受 limit 上限约束）。
     *
     * @param account 账号持久化行，不可为 {@code null}
     * @return 账号视图（不含凭据摘要与明文）
     */
    private ServiceAccountVO toView(ServiceAccountDO account) {
        return new ServiceAccountVO(account.id().toString(), account.account(), account.name(),
                account.tenantId().toString(), account.status(), account.audiences(), iso(account.expiresAt()),
                account.revision(), serviceAccountMapper.selectPermissionCodes(account.id()));
    }

    /**
     * 裁决本模块唯一权限码 {@code platform:service:write}。
     *
     * <p>判定依据是会话快照里已展开的权限码集合（不再查库），因此与账号在本请求开始后
     * 发生的授权变化无关。{@code actor} 为 {@code null}（拦截器未注入快照）与权限不足
     * 同样按 403 处理，未认证本身由拦截器在更早阶段以 401 拒绝。
     *
     * @param actor 当前会话快照，可为 {@code null}
     * @throws com.airagent.iam.web.error.ApiException 403 缺少权限或会话快照缺失
     */
    private void requireServiceWrite(CurrentSession actor) {
        if (actor == null || !actor.snapshot().permissions().contains(PERMISSION_SERVICE_WRITE)) {
            throw ApiException.forbidden("需要平台权限 platform:service:write");
        }
    }

    /**
     * 把申请的权限码解析为可授予的权限 id，并做越界整体拒绝。
     *
     * <p>先经 {@link #sanitizeAudiences} 消毒（同一套字符规则兼用于受众与权限码），
     * 空集合直接返回空列表（等价于建档时不授予任何权限，不发 SQL）。数据库解析按
     * “已启用 + 可下放 + 企业域”过滤；资源开通由写事务内统一检查，命中数少于申请数即存在未知、停用、平台专属或
     * 资源型权限码，整体 400 而不部分生效。
     *
     * <p>调用时机在开启事务之前，因此校验失败不会留下任何写入与审计。
     *
     * @param codes 请求中的权限码列表；{@code null} 视为空列表
     * @return 与命中码一一对应的权限 id（顺序由数据库返回顺序决定，不作保证）
     * @throws com.airagent.iam.web.error.ApiException 400 当任一码格式不合法，或存在不可授予的码
     */
    private List<UUID> resolvePermissionCodes(List<String> codes) {
        List<String> requested = sanitizeAudiences(codes);
        if (requested.isEmpty()) {
            return List.of();
        }
        List<UUID> ids = serviceAccountMapper.resolvePermissions(requested);
        if (ids.size() != requested.size()) {
            throw ApiException.badRequest("存在未知、停用、平台专属或不可下放权限码，服务账号不可授予");
        }
        return ids;
    }

    /**
     * 受众与权限码共用的消毒规则：逐项校验格式并按首次出现顺序去重。
     *
     * <p>合法元素须匹配 {@code [a-z0-9][a-z0-9.:-]{0,63}}，即以小写字母或数字开头、
     * 总长 1..64 字符，其后可含小写字母、数字、点、冒号与连字符。空白串、超长串与
     * {@code null} 元素都直接 400（错误消息会原样带出该元素，故调用方不得用本方法处理秘密）。
     *
     * @param values 原始列表；{@code null} 视为空列表
     * @return 去重保序的列表（入参为 {@code null} 时返回空列表），恒非 {@code null}
     * @throws com.airagent.iam.web.error.ApiException 400 当任一元素为 {@code null}、空白或格式不合法
     */
    private static List<String> sanitizeAudiences(List<String> values) {
        if (values == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String v : values) {
            if (v == null || v.isBlank() || v.length() > 64 || !v.matches("[a-z0-9][a-z0-9.:-]{0,63}")) {
                throw ApiException.badRequest("受众/权限码不合法: " + v);
            }
            if (!result.contains(v)) {
                result.add(v);
            }
        }
        return result;
    }

    /**
     * 在当前连接的事务内写入平台侧请求上下文（RLS 的唯一依据）。
     *
     * <p>租户固定为空、{@code is_platform} 为真：服务账号管理是平台线能力，
     * 可见范围由 {@code iam.service_accounts} 等表的“平台上下文”分支放行。
     * 每个事务的第一条语句必须调用本方法，否则直读结果为空。上下文只对当前会话生效，
     * 不能作为授权判断的替代品（权限已由 {@link #requireServiceWrite} 裁决）。
     *
     * @param userId 操作人用户 UUID，取自会话快照；写入 {@code app.user_id}
     */
    private void setPlatformContext(UUID userId) {
        requestContextMapper.setContext(userId, null, true);
    }

    /**
     * 与业务变更同事务写入一条审计记录。
     *
     * <p>detail 会先拷入新表并剔除值为 {@code null} 的项，再序列化为 JSON；
     * 调用方必须保证 detail 只含可公开展示的标识与时间——本模块的四条审计
     * （建档、签发、吊销、状态变更）均不写入明文密钥、摘要或口令类信息。
     * 请求标识取自日志上下文 MDC 的 {@code request_id}，缺失时写入 {@code null}。
     *
     * <p>审计写入失败（序列化异常或数据库异常）一律转为
     * {@link IllegalStateException} 抛出，使整个事务回滚，不允许出现“变更已落库而审计缺失”。
     *
     * @param tenantId   审计归属企业；平台维度的操作（吊销、状态变更）传 {@code null}，
     *                   由 RLS 的平台上下文放行
     * @param actor      操作人用户 UUID（会话主体）
     * @param action     动作码，取 {@code service_account.create}、{@code service_account.token_issue}、
     *                   {@code service_account.token_revoke}、{@code service_account.status_update}
     * @param targetType 目标类型，取 {@code service_account} 或 {@code service_token}
     * @param targetId   目标标识文本（账号 UUID 或凭据标识，均非秘密）
     * @param detail     附加信息键值对；{@code null} 等价于空对象
     * @throws IllegalStateException 当 detail 序列化或审计写入失败（事务需整体回滚）
     */
    void audit(UUID tenantId, UUID actor, String action, String targetType, String targetId,
               Map<String, Object> detail) {
        try {
            Map<String, Object> safeDetail = new LinkedHashMap<>(detail == null ? Map.of() : detail);
            safeDetail.values().removeIf(v -> v == null);
            eventMapper.insertAudit(tenantId, actor, action, targetType, targetId,
                    mapper.writeValueAsString(safeDetail), MDC.get("request_id"));
        } catch (RuntimeException e) {
            throw new IllegalStateException("审计写入失败（事务必须整体回滚）", e);
        }
    }

    /**
     * 时间统一格式化：换算到 UTC 后输出 ISO-8601 文本。
     *
     * <p>由 {@code java.time} 默认格式化生成，秒为 0 时该位会被省略，因此不保证定长；
     * 输出以 {@code Z} 结尾。入参为 {@code null} 时返回 {@code null}，
     * 使可选列（重叠上界、吊销时刻）在 JSON 中自然缺省而不是报错。
     *
     * @param value 数据库读到的时间戳；可为 {@code null}
     * @return UTC ISO-8601 文本，或 {@code null}
     */
    private static String iso(OffsetDateTime value) {
        return value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }
}
