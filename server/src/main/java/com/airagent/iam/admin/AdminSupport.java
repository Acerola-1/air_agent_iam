package com.airagent.iam.admin;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.web.error.ApiException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * 管理线共用：权限裁决、事务上下文、分页游标与同事务审计。
 * 菜单/按钮不可替代这里的服务端裁决；每次写操作都在调用方事务内显式设置可信上下文。
 */
@Component
public class AdminSupport {

    public static final int DEFAULT_LIMIT = 20;
    public static final int MAX_LIMIT = 200;

    private final AdminEventMapper eventMapper;
    private final ObjectMapper mapper;
    private final RequestContextMapper requestContextMapper;

    public AdminSupport(AdminEventMapper eventMapper, ObjectMapper mapper,
                        RequestContextMapper requestContextMapper) {
        this.eventMapper = eventMapper;
        this.mapper = mapper;
        this.requestContextMapper = requestContextMapper;
    }

    public void requirePermission(CurrentSession session, String code) {
        if (session == null || !session.snapshot().permissions().contains(code)) {
            throw ApiException.forbidden("缺少权限: " + code);
        }
    }

    public void requireAnyPermission(CurrentSession session, String... codes) {
        if (session == null) {
            throw ApiException.forbidden("未认证会话");
        }
        for (String code : codes) {
            if (session.snapshot().permissions().contains(code)) {
                return;
            }
        }
        throw ApiException.forbidden("缺少任一必需权限");
    }

    /** 当前必须已选择企业上下文；企业管理写操作不允许平台空上下文直写租户行。 */
    public UUID requireCurrentTenant(CurrentSession session) {
        UUID tenantId = session.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        return tenantId;
    }

    public void setContext(UUID userId, UUID tenantId, boolean platform) {
        requestContextMapper.setContext(userId, tenantId, platform);
    }

    public int clampLimit(Integer limit) {
        if (limit == null) {
            return DEFAULT_LIMIT;
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        return limit;
    }

    /** keyset 游标：base64url(上一页末行 id 的文本)，不透明、不接受排序语义。 */
    public String encodeCursor(String lastId) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(lastId.getBytes(StandardCharsets.UTF_8));
    }

    public String decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        try {
            return new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("cursor 不合法");
        }
    }

    public static UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest(field + " 不是合法 UUID");
        }
    }

    /** 角色/权限码列表消毒：去空白、去重、拒绝超长/非法字符。 */
    public static List<String> sanitizeCodes(java.util.List<String> codes) {
        if (codes == null) {
            return List.of();
        }
        java.util.List<String> result = new java.util.ArrayList<>();
        for (String code : codes) {
            if (code == null || code.isBlank() || code.length() > 64
                    || !code.matches("[a-z][a-z0-9:_-]{2,63}")) {
                throw ApiException.badRequest("角色/权限码不合法: " + code);
            }
            if (!result.contains(code)) {
                result.add(code);
            }
        }
        return result;
    }

    /**
     * 登记 Redis 键删除 outbox（同事务）。Sa-Token 键构形必须与 DigestStpLogic 一致：
     * Authorization:login:token:&lt;sha256-hex(rawToken)&gt;。
     */
    public void enqueueRedisDeletes(List<String> digests) {
        if (digests.isEmpty()) {
            return;
        }
        List<String> keys = digests.stream().map(digest -> "Authorization:login:token:" + digest).toList();
        eventMapper.enqueueRedisDeletes(mapper.writeValueAsString(Map.of("keys", keys)));
    }

    /** 审计写入失败必须令调用方事务整体回滚（异常向上传播，不吞）。 */
    public void audit(UUID tenantId, UUID actor, String action, String targetType, String targetId,
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
}
