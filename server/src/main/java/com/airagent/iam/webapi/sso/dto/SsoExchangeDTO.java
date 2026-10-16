package com.airagent.iam.webapi.sso.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * SSO 服务端兑换请求体（DTO，{@code POST /v1/internal/sso/exchange} 专用）。
 *
 * <p>分层位置：Controller 层原样透传给
 * {@link com.airagent.iam.webapi.sso.service.SsoExchangeService#exchange}，
 * 形状校验（必填与长度上界）在该服务内裁决，本类不带 Bean Validation 注解。
 * 三个字段都必填：任一为 {@code null} 或全空白即 400，请求体缺失同样 400。
 *
 * <p>线格式：本服务全局配置 {@code spring.jackson.property-naming-strategy=SNAKE_CASE}，
 * 因此 JSON 字段名为 {@code ticket}、{@code redirect_uri}、{@code state}，
 * 与冻结契约 {@code contracts/schemas/requests.schema.json} 的 {@code sso_exchange} 一致；
 * 注意契约把 {@code state} 列为可选、实现则按必填处理（见交接疑点）。
 *
 * <p>敏感数据边界：{@code ticket} 与 {@code state} 是一次性不透明凭据，明文只出现在
 * "回调 query → 消费方 BFF 服务端 → 本请求体"这条短链路，服务端两者都只以
 * {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 的 SHA-256 摘要入库与比对，
 * 原始值不写审计、不进日志。本类覆写 {@code toString()} 输出固定脱敏文本，
 * 令牌与 state 不会经日志或异常信息外泄。
 *
 * @param ticket      中央 303 回调下发的一次性票据（原始值约 43 字符 URL-safe Base64），
 *                    长度上界 256；配置 {@code iam.sso.ticket-ttl-seconds} 缺省 30 秒即失效，
 *                    且消费一次即作废
 * @param redirectUri 消费方回调地址，长度上界 512；必须与该客户端注册的
 *                    {@code callback_url} <em>精确</em>相等（非前缀），并参与 ticket 的原子领取条件
 * @param state       发起授权时由消费方生成、原样回传的一致性校验值，长度上界 256；
 *                    服务端按摘要原子消费，并要求其登记的客户端与回调与本请求一致
 * @author Acerola
 */
@Schema(name = "SsoExchangeDTO", description = "SSO 兑换请求：一次性 ticket、精确回调地址与 state。"
        + "三者均必填；ticket 与 state 只在本次请求体中出现，服务端仅按其摘要领取，不回显、不写日志")
public record SsoExchangeDTO(

        @Schema(description = "一次性票据原始值；过期或被使用后兑换返回 401",
                requiredMode = Schema.RequiredMode.REQUIRED,
                maxLength = 256,
                example = "fictional-ticket-0123456789abcdef")
        String ticket,

        @Schema(description = "回调地址，必须与注册 callback_url 精确相等，不一致返回 400",
                requiredMode = Schema.RequiredMode.REQUIRED,
                maxLength = 512,
                example = "http://127.0.0.1:19100/web-api/sso/callback/agent")
        String redirectUri,

        @Schema(description = "授权发起方生成并原样回传的 state；按摘要原子消费，与客户端或回调不匹配返回 400",
                requiredMode = Schema.RequiredMode.REQUIRED,
                maxLength = 256,
                example = "fictional-state-0123456789abcdef")
        String state
) {

    /**
     * 固定脱敏输出，防止一次性 ticket 与 state 经日志或异常信息外泄。
     *
     * @return 不含任何字段值的常量文本
     */
    @Override
    public String toString() {
        return "SsoExchangeDTO[sensitive fields redacted]";
    }
}
