package com.airagent.iam.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 本人改密请求体（DTO，{@code POST /v1/auth/change-password} 与浏览器同名端点共用）。
 *
 * <p>分层位置：Controller 原样透传；旧口令比对、新口令形状检查、会话撤销与摘要写入
 * 全部在 {@link com.airagent.iam.auth.service.SessionService#changePassword(String, ChangePasswordDTO)} 内完成。
 *
 * <p>敏感数据边界：两个字段都是明文口令。旧口令与权威快照里的 BCrypt 摘要在服务端内存中比对，
 * 新口令在比较相同时直接以 409 拒绝（比较发生在哈希之前）；两者都不落库为明文、不写日志、
 * 不进审计 detail，本类覆写 {@code toString()} 输出固定脱敏文本，永不回显。
 *
 * <p>改密后果：成功后该用户全部活跃会话（含本次调用的当前会话）被撤销，旧访问令牌立即失效。
 *
 * @param oldPassword 当前明文口令，必填；与数据库摘要不匹配返回 401
 * @param newPassword 新明文口令，必填，长度 8..256 字符（BCrypt 按 UTF-8 前 72 字节参与运算）；
 *                    与旧口令相同返回 409
 * @author Acerola
 */
@Schema(name = "ChangePasswordDTO", description = "本人改密请求：旧口令与新口令。两个口令字段只在请求体内出现，"
        + "响应、日志与 toString 均不回显；改密成功即撤销该用户全部会话（含当前会话）")
public record ChangePasswordDTO(

        @Schema(description = "当前明文口令，必填；与权威快照中的摘要不匹配返回 401（旧口令不正确）",
                requiredMode = Schema.RequiredMode.REQUIRED,
                writeOnly = true,
                example = "fictional-OldPassw0rd")
        String oldPassword,

        @Schema(description = "新明文口令，必填，8..256 字符；只以 BCrypt 摘要落库，不回显；与旧口令相同 409",
                requiredMode = Schema.RequiredMode.REQUIRED,
                writeOnly = true,
                example = "fictional-NewPassw0rd")
        String newPassword
) {

    /**
     * 固定脱敏输出，防止明文口令经日志或异常信息外泄。
     *
     * @return 不含任何字段值的常量文本
     */
    @Override
    public String toString() {
        return "ChangePasswordDTO[sensitive fields redacted]";
    }
}
