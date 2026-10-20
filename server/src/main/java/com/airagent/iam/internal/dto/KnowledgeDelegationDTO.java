package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 知识只读委托签发请求（DTO，{@code POST /v1/internal/knowledge-delegations}）。
 *
 * <p>{@code execution_context.verification_ref} 必须是当前调用客户端自己拥有的
 * {@code langgraph-runtime} 执行引用；{@code source_tenant_id} 是调用方声明并与引用/实时快照
 * 比较的当前企业，不构成授权。{@code operation} 只能取四个只读操作之一。
 *
 * @param schemaVersion    固定 {@code iam.knowledge-delegation-request.v1}
 * @param executionContext 源执行引用与四项修订基线
 * @param sourceTenantId   声明当前企业 UUID；与引用登记值不一致时拒绝签发
 * @param operation        单一操作：query / record:read / source:read / document:read
 */
@Schema(description = "知识只读委托签发请求。调用方必须持有自己名下的 runtime 执行引用与匹配的四项修订")
public record KnowledgeDelegationDTO(
        @Schema(description = "固定 iam.knowledge-delegation-request.v1",
                example = "iam.knowledge-delegation-request.v1")
        String schemaVersion,
        @Schema(description = "执行引用 + 四项修订基线")
        ExecutionContextRefDTO executionContext,
        @Schema(description = "声明当前企业 UUID，服务端与引用/实时快照比较",
                example = "01940000-0000-4000-8000-000000000001")
        String sourceTenantId,
        @Schema(description = "单一只读操作", example = "query")
        String operation
) {
    @Override
    public String toString() {
        return "KnowledgeDelegationDTO[sensitive fields redacted]";
    }
}
