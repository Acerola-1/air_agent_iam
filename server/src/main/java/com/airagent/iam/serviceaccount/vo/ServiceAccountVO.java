package com.airagent.iam.serviceaccount.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record ServiceAccountVO(
        String id,
        String account,
        String name,
        String tenantId,
        String status,
        List<String> audiences,
        String expiresAt,
        long revision,
        List<String> permissions
) {
}
