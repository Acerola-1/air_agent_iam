package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 平台账号建档请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：平台管理员创建后台账号（realm 固定 {@code workforce}），由
 * {@link com.airagent.iam.admin.controller.UserAdminController#create} 接收
 * （{@code POST /v1/admin/users} 与 {@code /web-api} 同名路径），交给
 * {@link com.airagent.iam.admin.service.UserAdminService#create} 裁决
 * {@code platform:user:write} 并开启事务。
 *
 * <p>口令只在请求与摘要生成的瞬间存在：服务层做强度校验后立即换成 BCrypt 摘要，
 * 明文不入库、不入日志、不入审计 detail。本类无校验注解，格式判定全在服务层；
 * 请求体可缺省（{@code @RequestBody(required = false)}），缺省返回 400。
 * 字段名按全局 SNAKE_CASE 解析（account / display_name / password）。
 *
 * @param account     登录账号，可打印 ASCII 3..64 字符，同 realm 内唯一
 * @param displayName 显示名，非空白且不超过 128 字符
 * @param password    初始明文口令，8..256 字符，仅用于生成摘要
 * @author Acerola
 */
@Schema(description = "平台账号建档请求。realm 固定 workforce；口令经强度校验后仅以 BCrypt 摘要落库，"
        + "响应与审计均不回显任何口令信息")
public record CreateUserDTO(

        @Schema(description = "登录账号：可打印 ASCII 字符 3..64 位（正则 \\p{Graph}{3,64}，与服务层和数据库 "
                + "users_account_ascii_ck 一致，不含空格与控制字符）。同 realm 内唯一，"
                + "重复触发 (realm, account) 唯一键返回 409。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "ops-alice")
        String account,

        @Schema(description = "显示名：非空白且不超过 128 字符，服务层裁决，缺失或越界返回 400。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "运维 Alice")
        String displayName,

        @Schema(description = "初始明文口令：长度 8..256 字符（与登录同形状校验，弱口令返回 400）。"
                + "按 UTF-8 取字节、超过 72 字节由 bcrypt 截断；服务端只存 $2b$ cost 10 摘要。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "n4ursery-pony-2026")
        String password
) {

    /**
     * 摘要化字符串，避免明文口令经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "CreateUserDTO[sensitive fields redacted]";
    }
}
