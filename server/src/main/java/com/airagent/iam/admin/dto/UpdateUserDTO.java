package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 平台账号局部更新请求体（DTO，PATCH 语义：{@code null} 组件保持原值）。
 *
 * <p>场景：改名或启停后台账号，由
 * {@link com.airagent.iam.admin.controller.UserAdminController#update} 接收
 * （{@code PATCH /v1/admin/users/{id}}），交给
 * {@link com.airagent.iam.admin.service.UserAdminService#update} 做 {@code platform:user:write}
 * 裁决、{@code SELECT ... FOR UPDATE} 行锁与修订比对。
 *
 * <p>副作用差异是刻意的：只有状态实际变化才会由触发器推进授权代次；置为
 * {@code disabled} 还会即时撤销目标账号全部活跃会话（含其自身会话），Redis 会话键删除
 * 经同事务 outbox 投递。请求体可缺省（{@code @RequestBody(required = false)}），缺省返回 400。
 * 字段名按全局 SNAKE_CASE 解析，数值组件不接受字符串形式。
 *
 * @param displayName      新显示名；{@code null} 表示不改
 * @param status           目标状态；{@code null} 表示不改；仅 active/disabled
 * @param expectedRevision 乐观并发基线（账号 auth_revision），见组件 {@code @Schema}
 * @author Acerola
 */
@Schema(description = "平台账号局部更新请求。display_name/status 均可省略（省略即不改）；"
        + "置为 disabled 会撤销目标全部活跃会话；可携带 expected_revision，不一致返回 409")
public record UpdateUserDTO(

        @Schema(description = "新的显示名：非空白且不超过 128 字符，越界返回 400；省略或 null 表示不改。"
                + "仅改显示名不触及授权列，因此不推进授权代次、不影响任何会话有效性。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "运维 Alice（值班）")
        String displayName,

        @Schema(description = "目标状态，真实枚举仅 active / disabled（企业用的是 active/suspended，勿混用）。"
                + "省略或 null 表示不改；其他取值返回 400。置为 disabled 触发授权代次 +1，"
                + "并由服务层撤销该账号全部活跃会话；若这是最后一名有效平台超级管理员，"
                + "guard_last_admin 触发器硬拒（409）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "disabled")
        String status,

        @Schema(description = "乐观并发基线：账号行当前的 auth_revision（口令、状态、角色变更与撤销会话"
                + "都会推进）。省略表示不做并发检查；与服务层加锁后读到的当前值不一致返回 409。"
                + "JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "4")
        Long expectedRevision
) {
}
