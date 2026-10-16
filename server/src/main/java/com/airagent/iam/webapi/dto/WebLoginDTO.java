package com.airagent.iam.webapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 浏览器 {@code POST /web-api/auth/login} 登录请求体（DTO）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.controller.WebApiAuthController#login}
 * 直接接收并转交 {@link com.airagent.iam.auth.service.SessionService#login}；本 DTO
 * 与 Bearer 面的 {@code LoginDTO} 语义一致，但受众由服务端固定为 {@code iam-admin}，
 * <em>不接受</em>客户端传入 audience——避免浏览器伪装其他受众。
 *
 * <p>口令只在服务端内存中短暂存在（BCrypt 校验后立即丢弃），Controller 与
 * 服务层的日志与审计 detail 均不回显；本类覆写 {@link #toString()} 输出固定脱敏文本，
 * 避免 {@code toString()} 被拼接进日志造成口令泄漏。
 *
 * @param account  登录账号，可打印 ASCII 3..64 字符；大小写敏感；JSON 字段 {@code account}
 * @param password 明文口令；长度受服务端 {@code PasswordHasher.validateStrength} 约束；
 *                 JSON 字段 {@code password}；不回显于任何响应/日志
 * @param realm    账号域；{@code null} 或空白由 Controller 归一化为 {@code workforce}，
 *                 当前人类账号仅此一域；JSON 字段 {@code realm}
 * @author Acerola
 */
@Schema(name = "WebLoginDTO", description = "浏览器登录请求：账号、明文口令与可选域；受众由服务端固定为 iam-admin")
public record WebLoginDTO(

        @Schema(description = "登录账号（可打印 ASCII 3..64 字符，大小写敏感）",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "zhang.acerola")
        String account,

        @Schema(description = "明文口令；服务端 BCrypt 校验后立即丢弃，绝不回显",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String password,

        @Schema(description = "账号域；缺省或空白视为 workforce（当前唯一人类域）",
                example = "workforce",
                nullable = true)
        String realm
) {
    /**
     * 固定脱敏输出，防止明文口令经日志或 {@code toString()} 拼接外泄。
     *
     * @return 不含任何字段值的常量文本
     */
    @Override
    public String toString() {
        return "WebLoginDTO[sensitive fields redacted]";
    }
}
