package com.airagent.iam.admin.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record PermissionVO(
        String code,
        String name,
        String grantScope,
        String resourceType
) {
}
