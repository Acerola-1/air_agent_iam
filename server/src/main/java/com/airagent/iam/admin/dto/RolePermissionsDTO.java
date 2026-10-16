package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 角色权限全量替换请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：重设某个自定义角色持有的权限集合，由
 * {@link com.airagent.iam.admin.controller.RoleAdminController#replacePermissions} 接收
 * （{@code POST /v1/admin/roles/{id}/permissions}），交给
 * {@link com.airagent.iam.admin.service.RoleAdminService#replacePermissions} 依据角色自身 scope
 * 在平台线（{@code platform:role:write}）或企业线（{@code tenant:role:write}）裁决。
 * 替换为 delete-then-insert，事务内完成；权限关系变化会推进所有引用该角色的账号/成员修订。
 *
 * <p>请求体可缺省（{@code @RequestBody(required = false)}），缺省即空集合 = 清空该角色全部权限；
 * 内置角色不可改动（403）。字段名按全局 SNAKE_CASE 解析（permission_codes）。
 *
 * @param permissionCodes 目标权限码集合；{@code null} 或空集合表示清空
 * @param expectedContext 资源写入时打开表单的会话上下文；非资源请求兼容省略
 * @param expectedTenantRevision 资源写入时目标企业授权修订；与操作者当前企业分别处理
 * @author Acerola
 */
@Schema(description = "角色权限全量替换请求。未知权限码 400；资源权限需企业独有角色与有效开通；给企业角色分配平台专属权限 409；"
        + "授予操作者自身不持有的权限 403；内置角色 403")
public record RolePermissionsDTO(

        @Schema(description = "目标权限码集合（全量替换，非增量）。码形状限 3..64 字符、小写字母开头、"
                + "可含小写字母/数字/:/_/-，须能在 iam.permissions 中命中，否则整批 400。"
                + "资源权限新增需企业开通、目录启用及可下放性，管理资格不要求自身已有读码；"
                + "企业角色只能拿 grantable_to_tenants 为 true 的权限。非平台超级管理员不得授出"
                + "自身权限快照之外的码（403）。null 或空数组表示清空该角色权限。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> permissionCodes,
        @Schema(description = "资源写入时必填：打开表单时的会话上下文") ExpectedContextDTO expectedContext,
        @Schema(description = "资源写入时必填：目标企业授权修订") Long expectedTenantRevision
) {
    /** 兼容既有非资源调用；资源写入必须使用完整构造器提供上下文和企业修订。 */
    public RolePermissionsDTO(List<String> permissionCodes) {
        this(permissionCodes, null, null);
    }

}
