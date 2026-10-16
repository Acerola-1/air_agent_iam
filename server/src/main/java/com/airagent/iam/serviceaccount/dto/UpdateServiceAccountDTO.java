package com.airagent.iam.serviceaccount.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 服务账号状态变更请求体（DTO，Controller → Service 入参，PATCH 局部更新）。
 *
 * <p>场景：停用或重新启用一个服务账号（{@code PATCH /{id}}）。这是账号主体上唯一可改的字段
 * ——显示名、受众、有效期与权限授予都不经本接口修改。由
 * {@link com.airagent.iam.serviceaccount.controller.ServiceAccountAdminController#updateStatus}
 * 接收，交给 {@link com.airagent.iam.serviceaccount.service.ServiceAccountService#updateStatus}
 * 裁决 {@code platform:service:write}。
 *
 * <p>停用只改变核验判定，不删除任何已签发凭据：数据库 {@code status} 允许
 * {@code active/disabled/revoked} 三种取值，但本接口只接受前两种，永久吊销凭据需逐个调用
 * 凭据吊销接口。请求体可缺省（返回 400）；不含 expected_revision，因此无乐观并发保护，
 * 每次成功调用都会把账号 {@code revision} +1。字段名按全局 SNAKE_CASE 解析（status）。
 *
 * @param status 目标状态，仅 {@code active} 或 {@code disabled}；其他取值（含 {@code revoked}、
 *               空白）返回 400
 * @author Acerola
 */
@Schema(description = "服务账号状态变更请求。只接受 active/disabled；不携带凭据与权限信息")
public record UpdateServiceAccountDTO(

        @Schema(description = "目标状态：active 重新启用，disabled 停用。停用后既有凭据仍在库中"
                + "（不被删除或改写），但下次凭据核验即返回 account_disabled；"
                + "取值由服务层校验，非法返回 400。",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "disabled"})
        String status
) {
}
