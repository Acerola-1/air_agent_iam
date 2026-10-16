package com.airagent.iam.serviceaccount.dto;

import java.util.List;

/** HTTP 请求参数。 */
public record CreateServiceAccountDTO(
        String account,
        String name,
        String tenantId,
        List<String> audiences,
        Integer expiresInDays,
        List<String> permissions
) {
}
