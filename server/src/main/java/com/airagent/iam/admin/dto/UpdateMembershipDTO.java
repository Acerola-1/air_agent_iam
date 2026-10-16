package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record UpdateMembershipDTO(
        String departmentId,
        String status,
        Long expectedRevision
) {
}
