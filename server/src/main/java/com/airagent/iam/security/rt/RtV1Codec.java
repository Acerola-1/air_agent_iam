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

/** 与原 Python 消费端兼容的 rt-v1：base64url({kid,p}).base64url(HMAC(第一段原文))。 */
public final class RtV1Codec {

    public static final String FORMAT = "rt-v1";
    private static final int MAX_TICKET_LENGTH = 8192;
    private static final long MAX_TTL_SECONDS = 60;
    private static final Set<String> FIELDS = Set.of("typ", "sid", "uid", "tid", "mid", "aud", "iat",
            "exp", "crev", "urev", "trev", "mrev");
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private RtV1Codec() {
    }

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
