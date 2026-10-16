package com.airagent.iam.security.rt;

/**
 * rt-v1 票据核验结论（安全层值对象，{@link RtV1Codec#verify} 的唯一返回类型；
 * 不是 HTTP 响应模型，无 Swagger 注解）。
 *
 * <p>设计取向：核验失败不抛异常，只返回本记录，让消费端能把"失败原因"稳定映射为自己的错误码；
 * 因此调用方必须先看 {@code ok}，不能凭 {@code body} 是否为空来推断成败。
 * {@code reason} 是封闭取值集合（见 {@link RtV1Codec#verify} 的枚举），与 Python 侧
 * {@code tools/rt-v1/rt_v1.py} 的分类基本对齐，差异两处：Java 另有 {@code bad_time}（60 秒时间窗），
 * 且把 Python 的 {@code bad_revision_<字段>} 细类与 {@code bad_time_type} 分别合并为
 * {@code bad_revision} 与 {@code malformed}。
 *
 * @param ok     是否通过全部校验；仅在 {@link RtV1Codec#verify} 走完签名、信封、字段、
 *               时效与修订全部判定后才为 {@code true}
 * @param reason 结论原因码；通过时恒为 {@code "ok"}，失败时为具体拒绝类别，
 *               不含票据片段、密钥或签名值
 * @param body   解出的票据正文；仅 {@code ok=true} 时非空，失败时一律为 {@code null}，
 *               调用方不得在未判 {@code ok} 时读取
 * @author Acerola
 */
public record RtV1VerifyResult(boolean ok, String reason, RtV1Body body) {

    /**
     * 构造一个失败结论（正文为空）。
     *
     * @param reason 失败原因码，取值须落在 {@link RtV1Codec#verify} 文档列出的集合内；
     *               本工厂不做取值校验，拼写错误会原样出现在结论里
     * @return {@code ok=false}、{@code body=null} 的结论对象
     */
    public static RtV1VerifyResult fail(String reason) {
        return new RtV1VerifyResult(false, reason, null);
    }
}
