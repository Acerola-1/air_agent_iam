package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 执行复查上下文（VO，内省响应体的 {@code execution_context} 段）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl} 在令牌内省
 * 携带 {@code include_execution_context=true} 时装配，随 {@code IdentityVO} 合并为同一
 * JSON 对象返回；复查模式不再返回本结构，而是返回
 * {@link RecheckActiveVO} / {@link RecheckInactiveVO}。
 *
 * <p>语义边界：{@code verificationRef} 是服务端登记的<b>非授权引用</b>——绑定登记客户端、
 * 受众、原会话与登记时刻的四项修订，只能由同一客户端以同一受众复查，不具有 Bearer 能力，
 * 不能创建新运行、签票或访问 {@code /me}。消费方不得把原始 {@code subject_token}、
 * 客户端凭据或任何密钥写入执行上下文/状态/checkpoint/Trace，能进入的只有引用标识与修订。
 *
 * <p>字段名按全局 SNAKE_CASE 输出（verification_ref / audience / session_id /
 * revisions / valid_until）。
 *
 * @param verificationRef 引用 id（UUID 文本），后续复查唯一需要回传的标识
 * @param audience        引用绑定的受众，复查请求必须给出完全相同的值，否则查不到引用
 * @param sessionId       原会话 id（UUID 文本），仅作关联与排障之用，不构成任何权限
 * @param revisions       登记时刻的四项修订基线，消费方须原样持有并在复查时回传
 * @param validUntil      引用失效时刻（UTC ISO-8601 文本），取 TTL（默认 43200 秒）与
 *                        会话绝对到期时刻的较小值；到期后复查判为不匹配，且不因复查而续期
 * @author Acerola
 */
@Schema(description = "执行复查上下文：服务端登记的非授权引用与其修订基线。引用不是票据，"
        + "有效期上界永不超过原会话")
public record ExecutionContextVO(

        @Schema(description = "执行引用 id（UUID 文本），仅原签发客户端以同一受众可复查",
                example = "55555555-5555-4555-8555-555555555555")
        String verificationRef,

        @Schema(description = "引用绑定的受众，复查时必须相同", example = "langgraph-runtime")
        String audience,

        @Schema(description = "原会话 id（UUID 文本），仅作关联用途，不构成权限",
                example = "7c1f2a3d-0000-4000-8000-000000000009")
        String sessionId,

        @Schema(description = "登记时刻的四项权威修订，消费方复查时原样回传")
        RevisionsDTO revisions,

        @Schema(description = "引用失效时刻（UTC ISO-8601 文本）；TTL 与会话绝对上界取小，不可续期",
                example = "2026-10-16T14:11:00Z")
        String validUntil
) {
}
