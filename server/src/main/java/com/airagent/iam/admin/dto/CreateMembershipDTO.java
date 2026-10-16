package com.airagent.iam.admin.dto;

import java.util.List;

/** HTTP 请求参数。 */
public record CreateMembershipDTO(
        String tenantId,
        String userId,
        String account,
        String displayName,
        String password,
        String departmentId,
        List<String> roleCodes
) {
    @Override
    public String toString() {
        return "CreateMembershipDTO[sensitive fields redacted]";
    }
}
