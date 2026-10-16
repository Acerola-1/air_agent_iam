package com.airagent.iam.admin.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record MemberVO(
        String id,
        String tenantId,
        UserVO user,
        String departmentId,
        String status,
        long revision,
        List<String> roles
) {
}
