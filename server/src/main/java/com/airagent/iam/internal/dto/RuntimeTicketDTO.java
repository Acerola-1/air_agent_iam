package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * rt-v1 运行票据签发请求体（DTO，{@code POST /v1/internal/runtime-tickets} 入参）。
 *
 * <p>分层位置：Controller 透传给
 * {@link com.airagent.iam.internal.service.RuntimeTicketService#issue}，由实现层做受众与
 * 客户端注册检查、主体实时核验、上下文一致性比较与签名。本类无校验注解。
 *
 * <p>使用场景：BFF 在把用户请求交给长运行运行时之前，用当前人类会话令牌换一张严格
 * 限定 {@code langgraph-runtime} 受众的短入口票据；该票据不能访问知识库或用户管理，
 * 也不能反向当作 {@code subject_token} 再次核验或签票。只有人类会话令牌可签——
 * 服务账号等机器令牌没有会话与企业上下文，一律拒绝。
 *
 * <p>字段名按全局 SNAKE_CASE 解析（subject_token / audience / target_tenant_id /
 * expected_ctx_version），数值组件不接受字符串形式。{@code subjectToken} 仅在传输中
 * 存在，服务层只按 SHA-256 摘要查库，原文不入日志、审计与响应。
 *
 * @param subjectToken     当前人类会话令牌原文（不透明随机串）；必填且非空白，缺失返回 400
 * @param audience         目标受众，必须恰为 {@code langgraph-runtime}，其余取值返回 400；
 *                         客户端另需已注册该受众，否则 403
 * @param targetTenantId   期望落入的企业 id（UUID 文本）；必填，非 UUID 返回 400，
 *                         与会话当前企业不一致返回 409
 * @param expectedCtxVersion 期望的会话上下文代次（会话纪元）；必填，与会话实际值不一致返回 409，
 *                           用于丢弃"切企业后迟到"的旧签票请求
 * @author Acerola
 */
@Schema(description = "运行票据签发请求。仅接受人类会话令牌，受众固定 langgraph-runtime；"
        + "target_tenant_id 与 expected_ctx_version 必须与会话当前权威状态一致，否则 409 失败关闭")
public record RuntimeTicketDTO(

        @Schema(description = "当前人类会话令牌原文（不透明随机串）；必填且非空白",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "3f7Y2sQ9xK1mNpRtVwZbLcDeGhJk")
        String subjectToken,

        @Schema(description = "目标受众，必须恰为 langgraph-runtime",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "langgraph-runtime")
        String audience,

        @Schema(description = "期望的企业 id（UUID 文本），必须等于会话当前企业",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "33333333-3333-4333-8333-333333333333")
        String targetTenantId,

        @Schema(description = "期望的会话上下文代次；JSON 数字，不接受字符串形式",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "7")
        Long expectedCtxVersion
) {

    /**
     * 摘要化字符串，避免 {@code subjectToken} 原文经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "RuntimeTicketDTO[sensitive fields redacted]";
    }
}
