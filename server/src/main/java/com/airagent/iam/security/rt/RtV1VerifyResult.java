package com.airagent.iam.security.rt;

/**
 * rt-v1 票据核验结论。reason 与 Python 侧 tools/rt-v1/rt_v1.py 的取值保持一致。
 */
public record RtV1VerifyResult(boolean ok, String reason, RtV1Body body) {

    public static RtV1VerifyResult fail(String reason) {
        return new RtV1VerifyResult(false, reason, null);
    }
}
