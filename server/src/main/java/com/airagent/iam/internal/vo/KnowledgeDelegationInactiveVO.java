package com.airagent.iam.internal.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 知识委托内省的失效信封（HTTP 仍为 200，消费方自行映射 401/403）。
 *
 * @param schemaVersion 固定 iam.knowledge-delegation-introspection.v1
 * @param active        恒为 false
 * @param reason        白名单原因码
 * @param evaluatedAt   服务端评估时刻
 */
@Schema(name = "KnowledgeDelegationInactiveVO", description = "委托无效：不泄露源用户其它信息")
public record KnowledgeDelegationInactiveVO(
        String schemaVersion,
        boolean active,
        String reason,
        String evaluatedAt) {
}
