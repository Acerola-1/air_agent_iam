package com.airagent.iam.admin.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record UserVO(
        String id,
        String realm,
        String account,
        String displayName,
        String status,
        long authRevision,
        List<String> platformRoles,
        String createdAt
) {
}
