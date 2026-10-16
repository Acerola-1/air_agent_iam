package com.airagent.iam.internal.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * rt-v1 运行票据签发响应（VO，{@code POST /v1/internal/runtime-tickets} 成功响应体）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.RuntimeTicketServiceImpl#issue} 在实时核验、
 * 上下文一致性与审计写入全部完成后装配，是签票用例唯一对外可见的结果。
 *
 * <p>票据形状（以实现 {@link com.airagent.iam.security.rt.RtV1Codec} 为准）：
 * 两段以 {@code .} 分隔——第一段是 {@code base64url(紧凑 JSON 信封)}（无填充），
 * 信封恰含两个键 {@code kid} 与 {@code p}；第二段是
 * {@code base64url(HMAC-SHA256(secret, 第一段原文的 ASCII 字节))}。
 * 因此 <b>HMAC 覆盖的是整个第一段（含 {@code kid}），而不只是正文</b>：换 {@code kid}
 * 即验签失败。正文 {@code p} 恰含 12 个字段
 * （typ/sid/uid/tid/mid/aud/iat/exp/crev/urev/trev/mrev），解析开启严格重复键检测，
 * 票据总长上限 8192 字符。
 *
 * <p>时效：{@code expiresIn} 为秒，取配置 TTL（钳制 1..60 秒）与"会话 idle/绝对到期最早上界"
 * 的较小值；核验侧还会拒绝 {@code exp - iat > 60} 与 {@code iat > now + 60} 的票据。
 * 票据到期不等于会话失效，会话仍有效时可重新核验后再签。
 *
 * <p>秘密边界：票据原文与签名密钥都不进入审计与日志（审计只记受众、目标企业与 TTL 秒数）；
 * {@code toString()} 已脱敏。票据只在传输与消费方内存中存活，不得写入 checkpoint/Trace。
 *
 * @param ticket    rt-v1 票据原文（{@code base64url(信封).base64url(签名)}），受众严格限定
 *                  {@code langgraph-runtime}，不可用于知识库或用户管理，也不可当作 subject_token 再核验
 * @param tokenType 承载方式，固定 {@code Bearer}（消费方以 {@code Authorization: Bearer <ticket>} 使用）
 * @param expiresAt 票据到期时刻（UTC ISO-8601 文本），等于 {@code iat + expiresIn}
 * @param expiresIn 有效期秒数（整数秒，1..60，已受会话剩余有效期收窄）
 * @param audience  票据受众，固定 {@code langgraph-runtime}
 * @param format    票据格式标识，固定 {@code rt-v1}，消费方按 issuer + format 路由到唯一权威核验路径
 * @author Acerola
 */
@Schema(description = "rt-v1 运行票据签发结果。ticket 为 base64url(信封).base64url(HMAC-SHA256) 两段串，"
        + "HMAC 覆盖含 kid 的整个第一段；有效期 1..60 秒且不超会话上界")
public record RuntimeTicketVO(

        @Schema(description = "rt-v1 票据原文（两段式，勿记录到日志/追踪）",
                example = "eyJraWQiOiJsb2NhbC0xIiwicCI6eyJ0eXAiOiJydC12MSIsIi4uLiI6Ii4uLn0.Zm9vYmFyYmF6c2ln")
        String ticket,

        @Schema(description = "承载方式，固定 Bearer", example = "Bearer")
        String tokenType,

        @Schema(description = "票据到期时刻（UTC ISO-8601 文本）", example = "2026-10-16T02:12:00Z")
        String expiresAt,

        @Schema(description = "有效期秒数，整数秒，1..60，且不超过会话剩余有效期", example = "60")
        long expiresIn,

        @Schema(description = "票据受众，固定 langgraph-runtime", example = "langgraph-runtime")
        String audience,

        @Schema(description = "票据格式标识，固定 rt-v1", example = "rt-v1")
        String format
) {

    /**
     * 摘要化字符串，避免票据原文经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "RuntimeTicketVO[sensitive fields redacted]";
    }
}
