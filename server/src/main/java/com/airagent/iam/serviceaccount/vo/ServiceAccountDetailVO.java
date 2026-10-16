package com.airagent.iam.serviceaccount.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record ServiceAccountDetailVO(
        ServiceAccountVO account,
        java.util.List<ServiceTokenVO> tokens
) {
}
