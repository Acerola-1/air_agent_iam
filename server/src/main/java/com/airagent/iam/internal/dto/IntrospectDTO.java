package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 主体实时核验请求体（DTO，{@code POST /v1/internal/identity/introspect} 入参）。
 *
 * <p>分层位置：Controller 原样透传给
 * {@link com.airagent.iam.internal.service.IntrospectionService#introspect}，
 * 由实现层校验形态并裁决；本类无校验注解，缺省与越界判定全在服务层。
 *
 * <p>双主体：调用服务的凭据在 {@code Authorization} 头，本类的 {@code subjectToken}
 * 是<b>被核验</b>的人类会话令牌或服务账号令牌，两者不得互换。
 *
 * <p>形态互斥：{@code subjectToken} 与 {@code executionContext} 必须且只能提供其一
 * （同时提供或同时缺失返回 400）——前者是令牌内省，后者是凭已登记
 * {@code verification_ref} 的执行复查。
 *
 * <p>字段名按全局 SNAKE_CASE 解析（subject_token / execution_context / audience /
 * expected_context / include_execution_context），数值组件不接受字符串形式。
 * {@code subjectToken} 只存在于请求传输瞬间：服务层仅取其 SHA-256 摘要查库，
 * 原始令牌不进日志、审计与响应。
 *
 * @param subjectToken            被核验的不透明令牌原文（人类会话令牌或服务账号令牌）；与
 *                                {@code executionContext} 二选一，另一形态下为 {@code null}
 * @param executionContext        执行复查上下文（引用 + 期望修订）；与 {@code subjectToken} 二选一
 * @param audience                本次核验的目标受众标识，必须在该客户端的注册受众白名单内，否则 403。
 *                                常见取值为 {@code langgraph-runtime} / {@code iam-admin} /
 *                                {@code air-agent} / {@code knowledge}；必填且不得为空白
 * @param expectedContext         调用方本地缓存的企业上下文基线；不一致时失败关闭返回 409，
 *                                不回新上下文。仅人类令牌可用（服务账号携带返回 400），可为 {@code null} 表示不校验
 * @param includeExecutionContext 是否要求额外登记并返回执行复查上下文；仅
 *                                {@code langgraph-runtime} 受众可用，其余受众取 {@code true} 返回 400。
 *                                {@code null} 与 {@code false} 等价，均不登记
 * @author Acerola
 */
@Schema(description = "内部核验请求。subject_token 与 execution_context 必须且只能提供其一；"
        + "audience 必填且须落在客户端注册受众白名单内。令牌原文仅存在于传输中，服务端只按摘要查库")
public record IntrospectDTO(

        @Schema(description = "被核验主体令牌原文（人类会话令牌或服务账号令牌），不透明随机串；"
                + "与 execution_context 二选一。缺失或空白在纯引用形态下属正常",
                example = "3f7Y2sQ9xK1mNpRtVwZbLcDeGhJk")
        String subjectToken,

        @Schema(description = "执行复查形态的请求体：verification_ref + expected_revisions 四项。"
                + "与 subject_token 互斥")
        ExecutionContextRefDTO executionContext,

        @Schema(description = "目标受众标识，必填且非空白；须为调用客户端已登记的受众之一，否则 403",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "langgraph-runtime")
        String audience,

        @Schema(description = "调用方缓存的企业上下文基线；与当前会话权威状态不一致返回 409（失败关闭）。"
                + "省略表示不做基线校验；服务账号令牌不支持该字段")
        ExpectedContextDTO expectedContext,

        @Schema(description = "是否登记并返回执行复查上下文；仅 langgraph-runtime 受众可用，"
                + "其余受众置 true 返回 400。null 等同 false",
                defaultValue = "false", example = "true")
        Boolean includeExecutionContext,

        @Schema(description = "知识委托内省时要求的单一操作；仅 kdl_ 前缀委托令牌必填，"
                + "普通令牌与服务账号请求保持省略",
                example = "query")
        String operation
) {

    /**
     * 兼容旧调用的五参数构造器（不含知识委托 operation）。
     *
     * @param subjectToken            被核验主体令牌
     * @param executionContext        执行复查上下文
     * @param audience                目标受众
     * @param expectedContext         企业上下文基线
     * @param includeExecutionContext 是否返回执行上下文
     */
    public IntrospectDTO(String subjectToken, ExecutionContextRefDTO executionContext,
                         String audience, ExpectedContextDTO expectedContext,
                         Boolean includeExecutionContext) {
        this(subjectToken, executionContext, audience, expectedContext,
                includeExecutionContext, null);
    }

    /**
     * 摘要化字符串，避免 {@code subjectToken} 等敏感原文经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "IntrospectDTO[sensitive fields redacted]";
    }
}
