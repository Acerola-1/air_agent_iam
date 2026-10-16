package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 企业成员局部更新请求体（DTO，PATCH 语义，但部门字段是全量替换）。
 *
 * <p>场景：调整成员在本企业内的部门挂靠与启停，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#updateMembership} 接收
 * （{@code PATCH /v1/admin/members/{id}}），交给
 * {@link com.airagent.iam.admin.service.TenantAdminService#updateMembership} 裁决
 * {@code tenant:member:write}、对成员行加锁并比对修订基线。
 *
 * <p>两个组件的缺省语义刻意不同：{@code status} 省略即不改（SQL 层 COALESCE），
 * 而 {@code departmentId} 省略会把挂靠部门置空（SQL 直接赋值）——只想改状态时必须把原部门
 * 一并回传。目标成员与写入租户恒取会话当前企业，载荷不能指定租户；
 * 跨企业成员 id 统一 404（不区分“不存在”与“不可见”）。请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省返回 400；字段名按全局 SNAKE_CASE 解析，
 * 数值组件不接受字符串形式。
 *
 * @param departmentId     新的部门 UUID 文本；{@code null}/空白表示清空挂靠
 * @param status           目标状态；{@code null} 表示不改；仅 active/disabled
 * @param expectedRevision 乐观并发基线（成员行 revision），{@code null} 表示不检查
 * @author Acerola
 */
@Schema(description = "企业成员局部更新请求。status 省略即不改；department_id 省略会被清空（全量替换语义），"
        + "只想改状态请回传原部门；可带 expected_revision，不一致返回 409")
public record UpdateMembershipDTO(

        @Schema(description = "新的部门挂靠 UUID：必须属于会话当前企业，否则 400"
                + "（数据库另有同租户复合外键）。注意本字段是全量替换而非增量——null、空白或省略"
                + "都会把成员从部门中摘出；想保持原挂靠必须原样回传当前部门 id。"
                + "部门实际变化时成员 revision +1。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "3f2b6a51-9a1e-4c7d-8b0f-2d5c7e9a1b40")
        String departmentId,

        @Schema(description = "成员在本企业内的状态，真实枚举仅 active / disabled"
                + "（账号用 disabled、企业用 suspended，三者勿混用）。省略或 null 表示不改；"
                + "其他取值返回 400。停用后该成员落在本企业的会话在下次权威核验被判为成员失效；"
                + "若这是企业最后一名有效 tenant_admin，guard_last_admin 触发器硬拒（409）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "disabled")
        String status,

        @Schema(description = "乐观并发基线：成员行当前的 revision（建档即为 1，部门/状态变更、"
                + "角色增删以及所关联角色的权限或状态变化都会使其 +1）。省略表示不做并发检查；"
                + "与服务层加锁后读到的当前值不一致返回 409。JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "2")
        Long expectedRevision
) {
}
