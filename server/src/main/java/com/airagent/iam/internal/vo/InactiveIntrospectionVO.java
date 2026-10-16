package com.airagent.iam.internal.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 主体失效信封（VO，令牌内省模式下 {@code active:false} 的唯一响应结构）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl} 的失效分支构造，
 * HTTP 状态仍是 200——契约上"核验已完成且结论为无效"不是协议错误。消费方必须把
 * {@code active:false} 映射为自身的 401/403，不得把内部 200 当业务成功。
 *
 * <p>信息最小化：本结构刻意不携带任何身份、企业、权限或 reason 之外的细节，
 * 使探测者无法区分"令牌不存在"与"令牌已撤销"。
 *
 * @param schemaVersion 结构版本标识，固定 {@code iam.introspection.v1}
 *                      （active 身份视图用的是另一个标识 {@code iam.identity.v1}）
 * @param active        恒为 {@code false}——有效主体走 {@code IdentityVO} /
 *                      {@code ServiceIdentityVO}，不使用本结构
 * @param reason        失效原因码，取值 {@code invalid_or_revoked} /
 *                      {@code account_disabled} / {@code tenant_suspended} /
 *                      {@code membership_disabled}（{@code context_required} 为契约保留值，
 *                      当前权威函数不产生）
 * @param evaluatedAt   服务端判定时刻（UTC ISO-8601 文本）
 * @author Acerola
 */
@Schema(description = "核验结论为无效的响应（HTTP 200）。不含任何身份细节，消费方须自行映射 401/403")
public record InactiveIntrospectionVO(

        @Schema(description = "结构版本，固定 iam.introspection.v1", example = "iam.introspection.v1")
        String schemaVersion,

        @Schema(description = "主体是否有效；本结构恒为 false")
        boolean active,

        @Schema(description = "失效原因：invalid_or_revoked（不存在/撤销/过期/代次变旧）、"
                + "account_disabled（账号停用）、tenant_suspended（企业停用）、"
                + "membership_disabled（成员关系停用）",
                example = "invalid_or_revoked",
                allowableValues = {"invalid_or_revoked", "account_disabled", "tenant_suspended",
                        "membership_disabled", "context_required"})
        String reason,

        @Schema(description = "服务端判定时刻（UTC ISO-8601 文本）", example = "2026-10-16T02:11:00Z")
        String evaluatedAt
) {
}
