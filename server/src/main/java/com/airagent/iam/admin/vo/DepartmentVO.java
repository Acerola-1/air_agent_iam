package com.airagent.iam.admin.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record DepartmentVO(
        String id,
        String tenantId,
        String parentId,
        String code,
        String name,
        String status
) {
}
