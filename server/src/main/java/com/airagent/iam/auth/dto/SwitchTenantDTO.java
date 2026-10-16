package com.airagent.iam.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 切换当前企业请求体（DTO，{@code POST /v1/auth/switch-tenant} 与浏览器同名端点共用）。
 *
 * <p>分层位置：Controller 原样透传；UUID 解析、成员/企业可用性与 CAS 在
 * {@link com.airagent.iam.auth.service.SessionService#switchTenant(String, SwitchTenantDTO)} 内完成，
 * 目标企业可用性最终由数据库函数 {@code iam_auth.switch_session_context} 裁决。
 *
 * <p>两个字段都必填，缺失返回 400。目标不是活跃企业或该用户不是活跃成员时数据库以 SQLSTATE
 * P0012 报错，译为 403；纪元基线不一致以 SQLSTATE P0010 报错，译为 409。切换只作用于中央会话，
 * 并经 {@code auth_sessions_synchronize_central} 触发器原子传播到同一中央会话下兑换出的应用子会话。
 *
 * @param tenantId           目标企业 UUID 文本，JSON 字段名 {@code tenant_id}；必填，
 *                           非 UUID 字符串返回 400，不存在或已停用返回 403
 * @param expectedCtxVersion 期望的会话上下文代次，JSON 字段名 {@code expected_ctx_version}；必填，
 *                           与当前 {@code auth_sessions.ctx_version} 不一致返回 409
 * @author Acerola
 */
@Schema(name = "SwitchTenantDTO", description = "切企业请求：目标企业加会话纪元基线，构成一次 CAS，"
        + "避免并发切换与续期互相覆盖")
public record SwitchTenantDTO(

        @Schema(description = "目标企业 UUID 文本，例如虚构值 01940000-0000-4000-8000-000000000001；"
                + "必须是当前用户的有效活跃成员关系所属企业",
                requiredMode = Schema.RequiredMode.REQUIRED,
                format = "uuid",
                example = "01940000-0000-4000-8000-000000000001")
        String tenantId,

        @Schema(description = "期望的会话上下文代次；缺失返回 400，与当前值不一致返回 409",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "3")
        Long expectedCtxVersion
) {
}
