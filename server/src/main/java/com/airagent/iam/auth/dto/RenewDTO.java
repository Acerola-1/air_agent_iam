package com.airagent.iam.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 会话续期请求体（DTO，{@code POST /v1/auth/renew} 与浏览器同名端点共用）。
 *
 * <p>分层位置：Controller 原样透传，CAS 比较与时限推进在
 * {@link com.airagent.iam.auth.service.SessionService#renew(String, RenewDTO)} 内由数据库函数
 * {@code iam_auth.renew_session} 完成。
 *
 * <p>该字段是会话纪元的乐观并发基线：与 {@code auth_sessions.ctx_version} 不一致时数据库以
 * SQLSTATE P0010 报错，经 {@link com.airagent.iam.web.error.PgErrorTranslator} 译为 409
 * （context_changed），调用方需重新拉取身份后重试。续期只延长空闲截止时间，绝不越过绝对上限。
 *
 * @param expectedCtxVersion 期望的会话上下文代次（{@code identity.session.ctx_version}），
 *                           JSON 字段名 {@code expected_ctx_version}；必填，缺失返回 400，
 *                           与当前值不一致返回 409
 * @author Acerola
 */
@Schema(name = "RenewDTO", description = "续期请求：仅携带会话纪元基线，防止与切企业并发互相覆盖")
public record RenewDTO(

        @Schema(description = "期望的会话上下文代次；请求体缺失该字段返回 400，与当前值不一致返回 409",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "3")
        Long expectedCtxVersion
) {
}
