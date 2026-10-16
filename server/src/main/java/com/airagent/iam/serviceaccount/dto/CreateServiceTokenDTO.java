package com.airagent.iam.serviceaccount.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 服务凭据签发请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：为已存在的服务账号签发一枚新凭据（{@code POST /{id}/tokens}），
 * 首次签发与轮换走同一接口——轮换只是“账号已有活跃凭据时再签一枚”。
 * 由
 * {@link com.airagent.iam.serviceaccount.controller.ServiceAccountAdminController#issueToken}
 * 接收，交给 {@link com.airagent.iam.serviceaccount.service.ServiceAccountService#issueToken}
 * 裁决 {@code platform:service:write} 并在服务账号行锁内完成。
 *
 * <p>本 DTO 不含任何秘密字段：明文密钥由服务端生成，只出现在响应
 * {@link com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO} 中一次。
 * 凭据自身的有效期不由调用方指定（固定 90 天并被账号到期与 365 天硬顶截断），
 * 请求里唯一可调的就是旧凭据的重叠窗口。请求体可缺省，等价于零窗口。
 * 字段名按全局 SNAKE_CASE 解析（overlap_hours）。
 *
 * @param overlapHours 旧活跃凭据的重叠窗口小时数；{@code null} 或 {@code 0} 均为零窗口
 *                     （旧凭据立即转为 revoked），合法范围 0..24，越界返回 400
 * @author Acerola
 */
@Schema(description = "凭据签发请求。只有一个可选字段：旧凭据的重叠窗口；不携带任何凭据内容")
public record CreateServiceTokenDTO(

        @Schema(description = "重叠窗口（小时），整数 0..24（含两端），越界返回 400；省略或 null 与 0 等价，"
                + "表示零窗口：此前全部活跃凭据立即被置为 revoked 并写入 revoked_at。"
                + "大于 0 时旧凭据保持 active，但其 overlap_until 被设为“本次轮换时刻 + 该小时数”"
                + "（不超过旧凭据自身到期时间），到点即判无效；窗口从轮换时刻起算，而非旧凭据最初签发时刻。"
                + "新签发的凭据本身不携带窗口。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "12")
        Integer overlapHours
) {
}
