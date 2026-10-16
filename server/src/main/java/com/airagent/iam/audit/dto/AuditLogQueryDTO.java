package com.airagent.iam.audit.dto;

import com.airagent.iam.web.error.ApiException;

/** 审计查询入参；界限校验也适用于非 HTTP 调用。 */
public record AuditLogQueryDTO(Integer limit, String cursor, String action) {

    private static final int MAX_PAGE_SIZE = 200;
    private static final int MAX_CURSOR_LENGTH = 64;
    private static final int MAX_ACTION_LENGTH = 128;

    public AuditLogQueryDTO {
        if (limit != null && (limit < 1 || limit > MAX_PAGE_SIZE)) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        if (cursor != null && cursor.length() > MAX_CURSOR_LENGTH) {
            throw ApiException.badRequest("cursor 不合法");
        }
        if (action != null && action.length() > MAX_ACTION_LENGTH) {
            throw ApiException.badRequest("action 不能超过 128 个字符");
        }
    }
}
