package com.airagent.iam.webapi.vo;

import com.airagent.iam.auth.vo.IdentityVO;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record WebRenewVO(
        String absoluteExpiresAt,
        String idleExpiresAt,
        IdentityVO identity
) {
}
