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
 * 服务账号与凭据管理（platform:service:write）。
 *
 * <p>原始令牌秘密仅在签发响应中出现一次；库内只存 sha256 摘要。
 * 期限默认 90 天、硬顶 365 天；轮换重叠窗口硬约束 24 小时；无永久凭据、不自动续期。
 */
@Service
public class ServiceAccountServiceImpl implements ServiceAccountService {

    static final String PERMISSION_SERVICE_WRITE = "platform:service:write";
    private static final int DEFAULT_EXPIRES_DAYS = 90;
    private static final int MAX_EXPIRES_DAYS = 365;
    private static final int MAX_OVERLAP_HOURS = 24;

    private final ServiceAccountMapper serviceAccountMapper;
    private final TenantMapper tenantMapper;
    private final RequestContextMapper requestContextMapper;
    private final AdminEventMapper eventMapper;
    private final TransactionTemplate tx;
    private final ObjectMapper mapper;

    public ServiceAccountServiceImpl(ServiceAccountMapper serviceAccountMapper, TenantMapper tenantMapper,
                                     RequestContextMapper requestContextMapper, AdminEventMapper eventMapper, TransactionTemplate tx, ObjectMapper mapper) {
        this.serviceAccountMapper = serviceAccountMapper;
        this.tenantMapper = tenantMapper;
        this.requestContextMapper = requestContextMapper;
        this.eventMapper = eventMapper;
        this.tx = tx;
        this.mapper = mapper;
    }

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
     * 停用/重新启用服务账号。停用即时生效（introspection 每次主库读状态返回 account_disabled），
     * 不删除既有凭据；revision 推进供审计与消费者识别。
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

    private static UUID parseSaId(String raw) {
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest("service_account_id 不是合法 UUID");
        }
    }

    private static int clampLimit(Integer limit) {
        if (limit == null) {
            return 20;
        }
        if (limit < 1 || limit > 200) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        return limit;
    }

    private static String encodeCursor(String lastId) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(lastId.getBytes(StandardCharsets.UTF_8));
    }

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

    private ServiceAccountVO loadView(UUID saId) {
        ServiceAccountDO account = serviceAccountMapper.selectById(saId);
        if (account == null) {
            throw ApiException.notFound("服务账号不存在");
        }
        return toView(account);
    }

    private ServiceAccountVO toView(ServiceAccountDO account) {
        return new ServiceAccountVO(account.id().toString(), account.account(), account.name(),
                account.tenantId().toString(), account.status(), account.audiences(), iso(account.expiresAt()),
                account.revision(), serviceAccountMapper.selectPermissionCodes(account.id()));
    }

    private void requireServiceWrite(CurrentSession actor) {
        if (actor == null || !actor.snapshot().permissions().contains(PERMISSION_SERVICE_WRITE)) {
            throw ApiException.forbidden("需要平台权限 platform:service:write");
        }
    }

    private List<UUID> resolvePermissionCodes(List<String> codes) {
        List<String> requested = sanitizeAudiences(codes);
        if (requested.isEmpty()) {
            return List.of();
        }
        List<UUID> ids = serviceAccountMapper.resolvePermissions(requested);
        if (ids.size() != requested.size()) {
            throw ApiException.badRequest("存在未知、停用、平台专属或资源型权限码，服务账号不可授予");
        }
        return ids;
    }

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

    private void setPlatformContext(UUID userId) {
        requestContextMapper.setContext(userId, null, true);
    }

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

    private static String iso(OffsetDateTime value) {
        return value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }
}
