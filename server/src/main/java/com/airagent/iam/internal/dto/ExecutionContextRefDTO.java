package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 执行复查形态的请求组件（DTO，{@code introspect} 请求体的 {@code execution_context} 字段）。
 *
 * <p>场景：长运行 Agent 在每次模型/MCP 发送、重试、子 Agent 前复查主体仍然有效，但不必
 * 反复回传原始 {@code subject_token}。引用由上一次合法的令牌内省（{@code include_execution_context=true}）
 * 在 IAM 侧登记产生，客户端无法自造 session/user/tenant 换取引用。
 *
 * <p>语义边界：引用本身<b>不具有 Bearer 能力</b>，不是新的离线授权票据，也不扩大任何权限；
 * 复查只返回原会话的实时权威结论。字段名按全局 SNAKE_CASE 解析（verification_ref / expected_revisions）。
 *
 * @param verificationRef   IAM 登记的执行引用 id（UUID 文本），绑定签发客户端、受众、原会话与当时的四项修订；
 *                          必填且非空白，缺失或空白返回 400，非 UUID 文本返回 400
 * @param expectedRevisions 客户端本地持有的原修订基线，四项全部必填（任一为 {@code null} 返回 400）；
 *                          必须同时等于引用登记值与当前权威快照值，否则复查结论为不匹配
 * @author Acerola
 */
@Schema(description = "执行复查请求组件：引用标识 + 期望的四项修订基线。引用不可离线自证权限，"
        + "只能由合法令牌的内省结果产生，且只在原签发客户端与原受众下可查")
public record ExecutionContextRefDTO(

        @Schema(description = "执行引用 id（UUID 文本），由服务端登记并绑定客户端/受众/会话/修订",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "55555555-5555-4555-8555-555555555555")
        String verificationRef,

        @Schema(description = "客户端缓存的原修订基线；四项均必填，与登记值或当前实时值任一不一致即复查失败",
                requiredMode = Schema.RequiredMode.REQUIRED)
        RevisionsDTO expectedRevisions
) {
}
