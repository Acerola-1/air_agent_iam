package com.airagent.iam.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 人类会话登录请求体（DTO，{@code POST /v1/auth/login} 与浏览器 {@code /web-api/auth/login} 共用）。
 *
 * <p>分层位置：Controller 层原样透传，字段合法性与限流全部在
 * {@link com.airagent.iam.auth.service.SessionService#login(LoginDTO)} 内裁决。
 * 四个字段都是必填：任一为 {@code null} 或不满足形状即 400，请求体缺失同样 400。
 *
 * <p>敏感数据边界：{@code password} 为明文口令，仅在本次请求内存中用于 BCrypt 校验
 * （超过 72 字节按 bcrypt 规则截断参与运算），既不落库也不写日志；本类覆写
 * {@code toString()} 输出固定脱敏文本，任何异常或日志打印都不会带出口令。
 * 账号不存在与口令错误返回完全相同的 401 消息，避免账号枚举。
 *
 * @param account  登录账号，可打印 ASCII 字符（正则 {@code \p{Graph}}）3..64 个；与 realm 联合唯一
 * @param password 明文口令，长度 8..256 字符；不回显、不入日志、toString 已脱敏
 * @param realm    账号域，当前仅支持 {@code workforce}，其余取值 400
 * @param audience 目标受众，仅 {@code air-agent} / {@code knowledge} / {@code iam-admin} 三者之一；
 *                 它写入会话的 login_audience 并决定身份视图的权限裁剪口径
 * @author Acerola
 */
@Schema(name = "LoginDTO", description = "登录请求：账号、明文口令、账号域与目标受众。口令只在传输与内存校验中出现，"
        + "响应、日志与 toString 均不回显")
public record LoginDTO(

        @Schema(description = "登录账号，可打印 ASCII 3..64 字符（同 realm 内唯一）",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "zhang.acerola")
        String account,

        @Schema(description = "明文口令，8..256 字符（BCrypt 按 UTF-8 前 72 字节参与运算）；"
                + "校验后立即丢弃，绝不回显、不落库、不写日志",
                requiredMode = Schema.RequiredMode.REQUIRED,
                writeOnly = true,
                example = "fictional-Passw0rd")
        String password,

        @Schema(description = "账号域，当前仅支持 workforce",
                requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = "workforce",
                example = "workforce")
        String realm,

        @Schema(description = "登录受众，决定会话受众与身份权限裁剪；非法取值 400",
                requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"air-agent", "knowledge", "iam-admin"},
                example = "iam-admin")
        String audience
) {

    /**
     * 固定脱敏输出，防止明文口令经日志或异常信息外泄。
     *
     * @return 不含任何字段值的常量文本
     */
    @Override
    public String toString() {
        return "LoginDTO[sensitive fields redacted]";
    }
}
