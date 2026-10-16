package com.airagent.iam.security.rt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * rt-v1 运行票据的无状态编解码工具（安全层，非 HTTP 端点模型，无 Swagger 注解），
 * 与原 Python 消费端 {@code tools/rt-v1/rt_v1.py} 逐字节兼容：
 * {@code base64url({kid,p}).base64url(HMAC(第一段 ASCII 原文))}。
 *
 * <p>信封形状（两段、以一个 {@code .} 分隔，不是 JWT）：
 * <ol>
 *   <li>第一段是紧凑 JSON {@code {"kid":<密钥标识>,"p":{<12 个正文字段>}}} 的字节序列
 *       （键序由 {@link LinkedHashMap} 固定为 {@code kid,p} 与正文声明顺序，无空白、无缩进），
 *       再经 <b>无填充</b> 的 base64url 编码；</li>
 *   <li>第二段是 HMAC-SHA256 的摘要，密钥为配置 {@code iam.rt.secret} 的 UTF-8 字节，
 *       <b>签名输入是第一段 base64url 文本本身的 ASCII 字节</b>（不是解码后的 JSON），
 *       摘要再经同一无填充 base64url 编码器输出，因此第二段恒为 43 个 ASCII 字符。</li>
 * </ol>
 * 签名覆盖的是"文本"而非"语义"：任何能解码出同一 JSON 但写法不同的第一段（例如补 {@code =} 填充
 * 或非规范尾比特）都是不同的签名输入，必然验签失败——规范化形式因此由签名强制，而非由解码器宽容。
 * {@link java.util.Base64#getUrlDecoder()} 只接受 URL 安全字母表，出现 {@code +}/{@code /}
 * 或非法字符抛异常，统一归入 {@code malformed}。
 *
 * <p>安全边界：
 * <ul>
 *   <li>算法固定为 HmacSHA256，信封内不含 {@code alg} 之类协商字段，不存在
 *       {@code alg:none} 或算法降级面；kid 只做密钥选择，不改变校验方式。</li>
 *   <li>验签在任何 JSON 解析与 base64url 解码<b>之前</b>完成，未认证字节不会进入解析器；
 *       解析器还开启了 {@link StreamReadFeature#STRICT_DUPLICATE_DETECTION}，重复键直接拒绝。</li>
 *   <li>签名比对走 {@link MessageDigest#isEqual}（定长、常量时间语义），且比对对象是摘要文本，
 *       与密钥原文无关。</li>
 *   <li>{@code kid} 不匹配只在验签通过后才可能被报出，伪造票据无法用来探测有效 kid。</li>
 *   <li>无状态、无撤销表：票据在 {@code exp} 之前始终可通过形状与签名校验，
 *       会话撤销只能靠消费方比对正文中的四项修订或回源内省；这正是 TTL 被压到 60 秒内、
 *       且不高于原会话最早到期时刻的原因。</li>
 *   <li>票据不是授权快照：正文只描述"某会话在某上下文代次下被核验过"，不含权限集合。</li>
 * </ul>
 *
 * <p>调用面：生产路径只用 {@link #sign(RtV1Body, String, byte[])}
 * （{@link com.airagent.iam.internal.service.impl.RuntimeTicketServiceImpl}）；
 * {@link #verify(String, String, byte[], String, long)} 服务于跨语言固定向量测试与消费端语义对齐，
 * Java 服务自身不在请求链路上验票。
 *
 * @author Acerola
 */
public final class RtV1Codec {

    /** 格式/类型标识，同时作为正文 {@code typ} 字段值，与 Python 侧常量一致。 */
    public static final String FORMAT = "rt-v1";

    /** 票据文本长度上限（字符）：超限直接判 {@code malformed}，作为进入任何解析前的资源护栏。 */
    private static final int MAX_TICKET_LENGTH = 8192;

    /**
     * 时间窗硬上界（秒）：要求 {@code exp - iat} 与 {@code iat - now} 都不超过它。
     * 与签发侧配置 {@code iam.internal.ticket-ttl-seconds} 的上界同值，防止超长票据绕过会话撤销。
     */
    private static final long MAX_TTL_SECONDS = 60;

    /** 正文合法键集：必须恰好这 12 个键，多一个少一个都是 {@code bad_fields}。 */
    private static final Set<String> FIELDS = Set.of("typ", "sid", "uid", "tid", "mid", "aud", "iat",
            "exp", "crev", "urev", "trev", "mrev");

    /** 共享的紧凑 JSON 读取器：开启重复键严格检测，含重复键的报文在解析阶段即失败。 */
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    /** base64url 无填充编码器，两段输出都走它，保证形状与 Python 侧 {@code b64url} 一致。 */
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** base64url 解码器（URL 安全字母表，允许缺填充），仅用于验签通过后的第一段。 */
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    /** 纯静态工具，禁止实例化。 */
    private RtV1Codec() {
    }

    /**
     * 装配信封并签发 rt-v1 票据。
     *
     * <p>正文字段的写出顺序固定（{@code typ,sid,uid,tid,mid,aud,iat,exp,crev,urev,trev,mrev}），
     * UUID 以 {@code toString()} 的小写连字符形式入串，整段 JSON 一次序列化后取
     * base64url 文本，签名即对该文本的 ASCII 字节做 HMAC-SHA256。
     *
     * @param body   票据正文，各组件均不得为 {@code null}（为空指针时序列化即抛运行时异常）；
     *               时间字段由调用方按 UTC 纪元秒给出，本方法不读时钟
     * @param kid    签名密钥标识，写入信封 {@code kid}，与配置 {@code iam.rt.kid} 一致；
     *               消费方按自身持有的 kid 比对，不匹配即拒
     * @param secret HMAC 密钥原文字节（由调用方从 {@code iam.rt.secret} 按 UTF-8 取字节），
     *               长度未在本层设限；空字节数组同样可运算，但等价于共享零熵，须由配置层杜绝
     * @return {@code 第一段.第二段} 形式的票据文本，不含填充字符与空白
     * @throws IllegalStateException JVM 不提供 HmacSHA256 实现（由 {@link #hmac} 抛出，
     *                               调用方按依赖不可用处理）
     */
    public static String sign(RtV1Body body, String kid, byte[] secret) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("typ", FORMAT);
        payload.put("sid", body.sid().toString());
        payload.put("uid", body.uid().toString());
        payload.put("tid", body.tid().toString());
        payload.put("mid", body.mid().toString());
        payload.put("aud", body.aud());
        payload.put("iat", body.iat());
        payload.put("exp", body.exp());
        payload.put("crev", body.crev());
        payload.put("urev", body.urev());
        payload.put("trev", body.trev());
        payload.put("mrev", body.mrev());
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("kid", kid);
        envelope.put("p", payload);
        String encoded = ENCODER.encodeToString(JSON.writeValueAsBytes(envelope));
        return encoded + "." + ENCODER.encodeToString(hmac(secret, encoded));
    }

    /**
     * 校验 rt-v1 票据的形状、签名、时效与修订下界，并解出正文。
     *
     * <p>判定顺序不可调换：长度/分段护栏 → <b>验签</b> → 信封与 kid → 正文键集与 {@code typ}
     * → 字段类型形状 → UUID 解析 → 受众 → {@code exp} → {@code iat<=exp} → 时间窗 →
     * {@code crev>=1} → 其余修订非负。任何一步失败都只返回结论对象，不抛异常，
     * 以便消费端把"拒绝原因"直接映射为自己的错误码。
     *
     * <p>与 Python 实现的取值差异（本侧更严或更粗）：Java 额外强制 60 秒时间窗（{@code bad_time}），
     * 并把 Python 的 {@code bad_revision_<字段>} 细类合并为 {@code bad_revision}；
     * 字段类型问题在本侧统一归 {@code malformed}（Python 用 {@code bad_time_type}）。
     *
     * @param ticket             票据原文；{@code null}、超过 8192 字符、或按 {@code .} 切分后
     *                           段数不等于 2 都为 {@code malformed}
     * @param kid                消费方期望的密钥标识，须与信封 {@code kid} 精确相等
     * @param secret             与 {@code kid} 对应的 HMAC 密钥字节；与签发侧同一口径（UTF-8 原文）
     * @param expectedAudience   期望受众；传 {@code null} 表示跳过受众校验（仅测试/工具场景），
     *                           非空时与正文 {@code aud} 不相等即 {@code bad_audience}
     * @param nowEpochSeconds    当前时刻，Unix 纪元秒（调用方时钟，UTC 口径，本方法不读系统时间）；
     *                           用于过期判定与 60 秒时间窗
     * @return 结论对象：通过时 {@code ok=true}、{@code reason="ok"}、{@code body} 为解出的正文；
     *         失败时 {@code ok=false}、{@code body=null}，{@code reason} 取以下之一——
     *         {@code malformed}（形状、编码、解析、UUID 或字段类型问题，含重复键）、
     *         {@code bad_signature}、{@code bad_kid}、{@code bad_fields}、
     *         {@code bad_audience}、{@code expired}（{@code now >= exp}）、
     *         {@code iat_after_exp}、{@code bad_time}（{@code iat > now+60} 或
     *         {@code exp-iat > 60}）、{@code crev_below_one}、{@code bad_revision}
     *         （{@code urev}/{@code trev}/{@code mrev} 为负）
     */
    public static RtV1VerifyResult verify(String ticket, String kid, byte[] secret,
                                          String expectedAudience, long nowEpochSeconds) {
        if (ticket == null || ticket.length() > MAX_TICKET_LENGTH) {
            return RtV1VerifyResult.fail("malformed");
        }
        String[] parts = ticket.split("\\.", -1);
        if (parts.length != 2) {
            return RtV1VerifyResult.fail("malformed");
        }
        try {
            byte[] expectedSignature = ENCODER.encode(hmac(secret, parts[0]));
            if (!MessageDigest.isEqual(parts[1].getBytes(StandardCharsets.US_ASCII), expectedSignature)) {
                return RtV1VerifyResult.fail("bad_signature");
            }
            JsonNode envelope = JSON.readTree(DECODER.decode(parts[0]));
            if (!envelope.isObject() || envelope.size() != 2 || !envelope.path("kid").isTextual()
                    || !kid.equals(envelope.path("kid").asText()) || !envelope.has("p")) {
                return RtV1VerifyResult.fail("bad_kid");
            }
            JsonNode payload = envelope.path("p");
            if (!payload.isObject() || payload.size() != FIELDS.size()
                    || !FIELDS.stream().allMatch(payload::has) || !FORMAT.equals(payload.path("typ").asText())) {
                return RtV1VerifyResult.fail("bad_fields");
            }
            for (String field : Set.of("sid", "uid", "tid", "mid", "aud")) {
                if (!payload.path(field).isTextual()) {
                    return RtV1VerifyResult.fail("malformed");
                }
            }
            for (String field : Set.of("iat", "exp", "crev", "urev", "trev", "mrev")) {
                if (!payload.path(field).isIntegralNumber() || !payload.path(field).canConvertToLong()) {
                    return RtV1VerifyResult.fail("malformed");
                }
            }
            RtV1Body body = new RtV1Body(UUID.fromString(payload.path("sid").asText()),
                    UUID.fromString(payload.path("uid").asText()), UUID.fromString(payload.path("tid").asText()),
                    UUID.fromString(payload.path("mid").asText()), payload.path("aud").asText(),
                    payload.path("iat").asLong(), payload.path("exp").asLong(), payload.path("crev").asLong(),
                    payload.path("urev").asLong(), payload.path("trev").asLong(), payload.path("mrev").asLong());
            if (expectedAudience != null && !expectedAudience.equals(body.aud())) {
                return RtV1VerifyResult.fail("bad_audience");
            }
            if (nowEpochSeconds >= body.exp()) {
                return RtV1VerifyResult.fail("expired");
            }
            if (body.iat() > body.exp()) {
                return RtV1VerifyResult.fail("iat_after_exp");
            }
            if (body.iat() > nowEpochSeconds + MAX_TTL_SECONDS
                    || body.exp() - body.iat() > MAX_TTL_SECONDS) {
                return RtV1VerifyResult.fail("bad_time");
            }
            if (body.crev() < 1) {
                return RtV1VerifyResult.fail("crev_below_one");
            }
            if (body.urev() < 0 || body.trev() < 0 || body.mrev() < 0) {
                return RtV1VerifyResult.fail("bad_revision");
            }
            return new RtV1VerifyResult(true, "ok", body);
        } catch (RuntimeException ex) {
            return RtV1VerifyResult.fail("malformed");
        }
    }

    /**
     * 对第一段文本的 ASCII 字节做 HMAC-SHA256，签名与验签共用，保证覆盖对象一致。
     *
     * @param secret 密钥字节，直接作为 {@link SecretKeySpec} 的原始密钥材料
     * @param body   待签名内容，即票据第一段（纯 base64url 字符，故 US-ASCII 编码无损）
     * @return 32 字节 HMAC 摘要原始值（未编码）
     * @throws IllegalStateException JVM 缺少 HmacSHA256 实现等 {@code GeneralSecurityException} 类故障，
     *                               原异常作为成因保留
     * @throws IllegalArgumentException 密钥字节数组为空（{@link SecretKeySpec} 拒绝空密钥）——
     *                                  该异常不在本方法内吞掉：签发侧直接冒泡，核验侧被
     *                                  {@link #verify} 的形状兜底捕获归为 {@code malformed}
     */
    private static byte[] hmac(byte[] secret, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(body.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 不可用", ex);
        }
    }
}
