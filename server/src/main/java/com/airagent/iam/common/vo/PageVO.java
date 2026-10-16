package com.airagent.iam.common.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record PageVO<T>(List<T> items, String nextCursor) {
}
