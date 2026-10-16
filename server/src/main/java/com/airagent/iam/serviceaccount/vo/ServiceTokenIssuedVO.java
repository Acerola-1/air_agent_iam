package com.airagent.iam.serviceaccount.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 凭据签发结果 HTTP 出参（VO，一次性披露明文密钥的唯一响应体）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl#issueToken}
 * 在事务内装配——{@code secret} 是调用数据库前刚生成的随机明文，代次与到期取自
 * {@link com.airagent.iam.serviceaccount.entity.IssuedTokenDO}（签发函数 RETURNING 的新行）。
 *
 * <p>场景：首次签发与轮换后的取密时刻，调用方必须立刻持久化 {@code secret}；本服务不提供
 * 任何“查看/再导出密钥”的接口。之后的管理查询只返回
 * {@link ServiceTokenVO} 元数据。
 *
 * <p>凭据边界（关键）：
 * <ul>
 *   <li>{@code secret} 为明文密钥，<b>只在本响应中出现一次</b>，之后不可再次读取；
 *       库内只存它的 SHA-256 十六进制摘要，Redis 与日志、审计 detail 都不含它；</li>
 *   <li>本类的 {@link #toString()} 已固定脱敏，不会打印任何组件值，异常与日志输出安全；</li>
 *   <li>响应体不应被缓存或落盘，调用方丢失后只能重新签发（轮换会按重叠窗口处置旧凭据）。</li>
 * </ul>
 *
 * @param credentialId       新凭据标识（{@code sak_} 加 32 位小写十六进制），非秘密，
 *                           吊销接口用它定位
 * @param secret             明文密钥本体：由安全随机数生成并以 URL-safe Base64 无填充编码，
 *                           服务端不保留副本，仅此一次返回
 * @param tokenType          令牌类型，恒为 {@code Bearer}，提示调用方以 Bearer 方式携带
 * @param expiresAt          新凭据的到期时刻，UTC ISO-8601 文本；以数据库回显值为准，
 *                           秒为 0 时省略该位
 * @param overlapUntil       本次施加给<b>被取代旧凭据</b>的重叠上界，UTC ISO-8601 文本；
 *                           零窗口（省略或 0）时为 {@code null}。新凭据自身不携带窗口，
 *                           该字段不是新凭据的到期时间
 * @param credentialRevision 新凭据在账号内的代次（已有最大值 +1，首次为 1）
 * @author Acerola
 */
@Schema(description = "凭据签发结果。secret 是明文密钥，服务端仅在本次响应中披露一次，"
        + "库内只存摘要，任何接口都无法再次取回；请调用方立即安全保存")
public record ServiceTokenIssuedVO(
        @Schema(description = "新凭据标识（sak_ + 32 位小写十六进制），可公开展示，不是秘密",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String credentialId,

        @Schema(description = "明文密钥：URL-safe Base64 无填充的安全随机串，仅此一次返回，"
                + "不可再次读取。服务端只保存其 SHA-256 摘要用于核验，不保存明文。",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String secret,

        @Schema(description = "令牌类型，恒为 Bearer", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"Bearer"})
        String tokenType,

        @Schema(description = "新凭据到期时间，UTC ISO-8601 文本（秒为 0 时省略该位）", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String expiresAt,

        @Schema(description = "施加于被本次签发取代的旧凭据的重叠上界，UTC ISO-8601 文本；"
                + "零窗口（省略或 0 小时）时为 null。新凭据本身不受此列约束。", format = "date-time")
        String overlapUntil,

        @Schema(description = "新凭据代次，账号内从 1 起递增", requiredMode = Schema.RequiredMode.REQUIRED)
        long credentialRevision
) {

    /**
     * 摘要化字符串，避免明文密钥经 {@code toString()} 进入日志或异常信息。
     *
     * <p>本视图唯一一次承载 {@code secret}，因此整个对象一律脱敏，不区分字段。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "ServiceTokenIssuedVO[sensitive fields redacted]";
    }
}
