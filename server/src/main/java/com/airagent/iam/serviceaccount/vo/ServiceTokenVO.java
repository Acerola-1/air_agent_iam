package com.airagent.iam.serviceaccount.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 服务凭据元数据 HTTP 出参（VO，仅在账号详情中出现）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl#get}
 * 从 {@link com.airagent.iam.serviceaccount.entity.ServiceTokenDO} 逐行装配，
 * 时间是 UTC ISO-8601 文本（数据库 timestamptz 换算而来）。
 *
 * <p>场景：详情页的凭据列表，用于展示“签发了几枚、哪枚还活跃、哪枚被轮换吊销、窗口到什么时候”。
 *
 * <p>凭据边界：本 VO <b>不含</b>明文密钥与 {@code token_digest} 摘要，{@code credentialId}
 * 只是可公开展示的标识（不是秘密，凭它无法核验或反推密钥）。明文密钥只在
 * {@link ServiceTokenIssuedVO} 中出现一次，本结构无法用来回取任何已签发凭据的内容。
 *
 * @param credentialId       凭据标识，形如 {@code sak_} 加 32 位小写十六进制，全库唯一；
 *                           吊销接口以此为入参
 * @param credentialRevision 该账号内的凭据代次，从 1 起递增；签发新凭据即推进，与账号级
 *                           {@code revision} 无关
 * @param status             凭据状态，仅 {@code active} / {@code revoked}。轮换（零窗口）与显式吊销
 *                           都会让旧凭据变成 revoked
 * @param issuedAt           签发时刻，UTC ISO-8601 文本（秒为 0 时省略该位，不保证定长）
 * @param expiresAt          到期时刻，到点即判无效，不因账号续期而延长
 * @param overlapUntil       轮换重叠上界：{@code null} 表示该凭据未被设置窗口（新签发的凭据恒为
 *                           {@code null}）；非空时它以“轮换时刻 + 窗口小时数”与自身到期时间的较小者
 *                           为准，到点即失效，即便 {@code status} 仍为 active
 * @param revokedAt          吊销时刻；{@code null} 表示未显式吊销。零窗口轮换会立即写入该列
 * @author Acerola
 */
@Schema(description = "凭据元数据视图：只有标识、代次、状态与时间列，不含明文密钥与摘要")
public record ServiceTokenVO(
        @Schema(description = "凭据标识（sak_ + 32 位小写十六进制），可公开展示，不是秘密",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String credentialId,

        @Schema(description = "凭据代次，账号内从 1 起递增，与账号修订号无关",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long credentialRevision,

        @Schema(description = "凭据状态；revoked 表示已吊销（显式吊销或零窗口轮换）",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "revoked"})
        String status,

        @Schema(description = "签发时间，UTC ISO-8601 文本（秒为 0 时省略该位）", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String issuedAt,

        @Schema(description = "到期时间，UTC ISO-8601 文本；到点核验即失效", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String expiresAt,

        @Schema(description = "轮换重叠上界，UTC ISO-8601 文本；null 表示未设置窗口。"
                + "窗口只写在被取代的旧凭据上，且从轮换时刻起算；新签发的凭据该列恒为 null",
                format = "date-time")
        String overlapUntil,

        @Schema(description = "吊销时间，UTC ISO-8601 文本；null 表示尚未吊销", format = "date-time")
        String revokedAt
) {
}
