package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 调用方上下文基线（DTO，{@code introspect} 请求体的 {@code expected_context} 字段）。
 *
 * <p>场景：下游服务本地缓存了一份身份/菜单，核验时把自己看到的上下文回传做一致性检查，
 * 避免"用旧企业的权限在新企业里继续跑"。仅适用于人类会话令牌；服务账号令牌携带本字段直接 400。
 *
 * <p>判定口径（见
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl}）：当前会话必须
 * 已选择企业，且企业 id 与上下文代次（会话纪元）都与基线一致；任一不符即失败关闭返回 409
 * {@code context_changed}，响应中不回显新的上下文细节。省略本字段表示不做一致性校验。
 *
 * <p>字段名按全局 SNAKE_CASE 解析（tenant_id / ctx_version），数值组件不接受字符串形式。
 *
 * @param tenantId   调用方认为的当前企业 id（UUID 文本）；非 UUID 文本返回 400。会话未选择企业时
 *                   一律判为不一致（409）
 * @param ctxVersion 调用方认为的会话上下文代次；首次登录为 1，每次成功切换企业 +1。
 *                   {@code null} 按"无匹配值"参与比较（与会话实际代次不可能相等）
 * @author Acerola
 */
@Schema(description = "调用方持有的企业上下文基线，用于乐观一致性检查；不一致返回 409 且不回新上下文")
public record ExpectedContextDTO(

        @Schema(description = "期望的当前企业 id（UUID 文本）",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "33333333-3333-4333-8333-333333333333")
        String tenantId,

        @Schema(description = "期望的会话上下文代次（会话纪元）；JSON 数字，不接受字符串形式",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "7")
        Long ctxVersion
) {
}
