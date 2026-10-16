package com.airagent.iam.audit.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.entity.AuditLogDO;
import com.airagent.iam.audit.mapper.AuditLogMapper;
import com.airagent.iam.audit.service.AuditService;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.error.ApiException;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/** 在同一连接、同一事务中完成权限裁决、RLS 上下文与有界查询。 */
@Service
public class AuditServiceImpl implements AuditService {

    private static final String PLATFORM_AUDIT_PERMISSION = "platform:audit:read";
    private static final String TENANT_AUDIT_PERMISSION = "tenant:audit:read";

    private final AuditLogMapper auditLogMapper;
    private final RequestContextMapper requestContextMapper;
    private final AdminSupport support;
    private final ObjectMapper objectMapper;

    public AuditServiceImpl(AuditLogMapper auditLogMapper, RequestContextMapper requestContextMapper,
                            AdminSupport support, ObjectMapper objectMapper) {
        this.auditLogMapper = auditLogMapper;
        this.requestContextMapper = requestContextMapper;
        this.support = support;
        this.objectMapper = objectMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public PageVO<AuditLogVO> list(CurrentSession actor, AuditLogQueryDTO query) {
        support.requireAnyPermission(actor, PLATFORM_AUDIT_PERMISSION, TENANT_AUDIT_PERMISSION);
        boolean platform = actor.snapshot().permissions().contains(PLATFORM_AUDIT_PERMISSION);
        UUID tenantId = platform ? null : support.requireCurrentTenant(actor);
        int limit = support.clampLimit(query.limit());
        Long beforeId = parseCursor(query.cursor());
        String actionPattern = query.action() == null ? null : query.action().replace('*', '%');
        requestContextMapper.setContext(actor.userId(), tenantId, platform);
        List<AuditLogDO> rows = auditLogMapper.selectPage(beforeId, actionPattern, limit + 1);
        boolean hasMore = rows.size() > limit;
        List<AuditLogVO> items = rows.stream().limit(limit).map(this::toView).toList();
        String next = hasMore
                ? support.encodeCursor(Long.toString(items.getLast().id())) : null;
        return new PageVO<>(items, next);
    }

    private Long parseCursor(String cursor) {
        String decoded = support.decodeCursor(cursor);
        if (decoded == null) {
            return null;
        }
        try {
            long value = Long.parseLong(decoded);
            if (value <= 0) {
                throw ApiException.badRequest("cursor 不合法");
            }
            return value;
        } catch (NumberFormatException ex) {
            throw ApiException.badRequest("cursor 不合法");
        }
    }

    private AuditLogVO toView(AuditLogDO row) {
        return new AuditLogVO(row.id(), row.tenantId() == null ? null : row.tenantId().toString(),
                row.actorUserId() == null ? null : row.actorUserId().toString(), row.actorType(),
                row.action(), row.targetType(), row.targetId(), objectMapper.readTree(row.detailJson()),
                row.requestId(), row.createdAt().withOffsetSameInstant(ZoneOffset.UTC).toString());
    }
}
