package com.airagent.iam.auth.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record TenantMembershipVO(
        String tenantId,
        String code,
        String name,
        String status,
        String memberStatus,
        boolean isOwner
) {
}
