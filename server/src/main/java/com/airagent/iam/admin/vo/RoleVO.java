package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 角色 HTTP 出参（VO，对外响应模型）。
 *
 * <p>覆盖平台角色与企业角色两种 scope：平台角色不属于任何企业（{@code tenantId} 为 {@code null}），
 * 企业角色要么是本企业自定义角色（tenantId 为该租户），要么是跨企业共享的内置模板
 * （tenantId 为 {@code null} 且 {@code builtin} 为真）。响应内联该角色当前的权限码，
 * 因此前端无需再逐角色调用权限目录。
 *
 * @param id              角色 UUID 文本（主键，服务端生成）
 * @param code            角色码，3..64 位小写字母数字与 {@code _ -}；平台 scope 下全库唯一，
 *                        企业 scope 下企业内唯一
 * @param scope           角色归属域，仅 {@code platform} / {@code tenant}；决定可授予对象与可装配权限范围
 * @param tenantId        归属企业 UUID 文本；平台角色与内置企业模板为 {@code null}
 * @param name            角色名称，非空且最长 128 字符
 * @param description     角色说明；列缺省为空字符串，不会为 {@code null}
 * @param builtin         是否内置角色。内置模板（如 {@code platform_super_admin}、{@code tenant_admin}）
 *                        不可改名、停用或调整权限，写操作一律 403
 * @param status          角色状态，仅 {@code active} / {@code disabled}；停用后不可再被授予，
 *                        且已持有者的授权代次会被推进
 * @param permissionCodes 该角色当前装配的权限码（按码升序）；未装配时为空列表
 * @author Acerola
 */
@Schema(description = "角色视图（平台/企业两种 scope，内联已装配权限码）")
public record RoleVO(
        @Schema(description = "角色 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "角色码，3..64 位小写字母数字与 _ -", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "角色归属域，决定可授予对象与可装配权限范围", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"platform", "tenant"})
        String scope,
        @Schema(description = "归属企业 UUID；平台角色与内置企业模板为 null", accessMode = Schema.AccessMode.READ_ONLY)
        String tenantId,
        @Schema(description = "角色名称，非空且最长 128 字符", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "角色说明，未填写时为空字符串", requiredMode = Schema.RequiredMode.REQUIRED)
        String description,
        @Schema(description = "是否内置角色；内置角色的改名、停用与权限调整一律被拒绝",
                requiredMode = Schema.RequiredMode.REQUIRED)
        boolean builtin,
        @Schema(description = "角色状态；disabled 会推进所有持有该角色的主体授权代次",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "disabled"})
        String status,
        @Schema(description = "该角色当前装配的权限码（按码升序），可为空数组", requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> permissionCodes,
        @Schema(description = "权限状态明细，区分已配置与当前有效；可为空数组")
        List<PermissionStateVO> permissionStates
) {
}
