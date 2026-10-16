package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 管理员重置他人口令请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：平台管理员为某个后台账号设置新口令，由
 * {@link com.airagent.iam.admin.controller.UserAdminController#resetPassword} 接收
 * （{@code POST /v1/admin/users/{id}/password}，成功 204 无响应体），交给
 * {@link com.airagent.iam.admin.service.UserAdminService#resetPassword} 裁决
 * {@code platform:user:password:reset}（与写权限分开的独立权限码）。
 *
 * <p>目标账号 id 走路径变量，不在本载荷内；摘要写入必须经 SECURITY DEFINER 函数
 * {@code iam_auth.set_user_password}（iam_app 无 password_hash 列写权限）。
 * 请求体可缺省（{@code @RequestBody(required = false)}），缺省或 new_password 为 null 均返回 400。
 * 字段名按全局 SNAKE_CASE 解析，数值组件不接受字符串形式。
 *
 * @param newPassword      新明文口令，8..256 字符，仅用于生成 BCrypt 摘要
 * @param expectedRevision 乐观并发基线（账号 auth_revision），{@code null} 表示不检查
 * @author Acerola
 */
@Schema(description = "管理员重置口令请求。改密会使目标账号全部活跃会话（含其自身当前会话）立即失效；"
        + "响应不回显任何口令信息")
public record ResetPasswordDTO(

        @Schema(description = "新明文口令：长度 8..256 字符，弱口令返回 400。服务端只生成 $2b$ cost 10 摘要，"
                + "明文不落库、不入日志与审计 detail（重置的审计 detail 为空对象）。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "n4ursery-pony-2026")
        String newPassword,

        @Schema(description = "乐观并发基线：账号行当前的 auth_revision。省略表示不做并发检查；"
                + "与服务层加锁后读到的当前值不一致返回 409。注意改密与随后的撤销会话会连续推进代次。"
                + "JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "4")
        Long expectedRevision
) {

    /**
     * 摘要化字符串，避免新明文口令经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "ResetPasswordDTO[sensitive fields redacted]";
    }
}
