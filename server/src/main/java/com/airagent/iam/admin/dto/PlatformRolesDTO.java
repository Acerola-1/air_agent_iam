package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 平台角色全量替换请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：把某个后台账号的平台角色集合整体换成给定值，由
 * {@link com.airagent.iam.admin.controller.UserAdminController#replacePlatformRoles} 接收
 * （{@code POST /v1/admin/users/{id}/platform-roles}），交给
 * {@link com.airagent.iam.admin.service.UserAdminService#replacePlatformRoles} 裁决
 * {@code platform:user:role:assign}。替换是 delete-then-insert，持锁事务内完成，失败整体回滚。
 *
 * <p>本接口只处理 {@code scope = platform} 的角色（关系表为 iam.user_roles），
 * 与企业角色（iam.membership_roles）分属两套授权；请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省即空集合 = 清空全部平台角色。
 * 字段名按全局 SNAKE_CASE 解析（role_codes / expected_revision）。
 *
 * @param roleCodes        目标平台角色码集合；{@code null} 或空集合表示清空
 * @param expectedRevision 乐观并发基线（账号 auth_revision）；{@code null} 表示不检查
 * @author Acerola
 */
@Schema(description = "平台角色全量替换请求。未知/停用角色码返回 400；非平台超级管理员只能授予"
        + "自身权限集合之内的角色，越界返回 403；替换后账号授权代次 +1，旧权限快照即刻失效")
public record PlatformRolesDTO(

        @Schema(description = "目标平台角色码集合（全量替换，非增量）。码形状限 3..64 字符、"
                + "小写字母开头、可含小写字母/数字/:/_/-；只接受 scope=platform 且 status=active 的角色，"
                + "出现未知或停用码整批返回 400（不部分生效）。null 或空数组表示清空该账号全部平台角色；"
                + "若这会移除最后一名有效平台超级管理员，guard_last_admin 触发器硬拒（409）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> roleCodes,

        @Schema(description = "乐观并发基线：账号行当前的 auth_revision。省略表示不做并发检查；"
                + "与服务层加锁后读到的当前值不一致返回 409。JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "4")
        Long expectedRevision
) {
}
