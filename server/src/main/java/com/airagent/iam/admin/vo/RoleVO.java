package com.airagent.iam.admin.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record RoleVO(
        String id,
        String code,
        String scope,
        String tenantId,
        String name,
        String description,
        boolean builtin,
        String status,
        List<String> permissionCodes
) {
}
