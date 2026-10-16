package com.airagent.iam.security;

import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.rt.RtV1Body;
import com.airagent.iam.security.rt.RtV1Codec;
import com.airagent.iam.security.rt.RtV1VerifyResult;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C02/C03：bcrypt $2b$ 与 rt-v1 跨语言固定向量。
 * Python 向量由 tools/bcrypt-vectors/bcrypt_vectors.py generate 与
 * tools/rt-v1/rt_v1.py generate 生成；本测试同时写出 Java 向量供 Python 反向核验。
 */
class CrossLanguageVectorTest {

    private static final Path SERVER_DIR = Path.of("").toAbsolutePath();
    private static final Path TOOLS_DIR = SERVER_DIR.getParent().resolve("tools");
    private static final ObjectMapper JSON = JsonMapper.builder().build();

    @Test
    void bcryptPythonVectorsVerifyInJava() throws IOException {
        PasswordHasher hasher = new PasswordHasher();
        JsonNode doc = JSON.readTree(Files.readString(
                TOOLS_DIR.resolve("bcrypt-vectors/out/bcrypt-py-vectors.json")));
        List<String> wrong = new ArrayList<>();
        doc.get("wrong_passwords_utf8_hex").forEach(n ->
                wrong.add(new String(HexFormat.of().parseHex(n.asText()), StandardCharsets.UTF_8)));

        List<Map<String, String>> javaCases = new ArrayList<>();
        for (JsonNode c : doc.get("cases")) {
            String password = new String(HexFormat.of().parseHex(c.get("password_utf8_hex").asText()),
                    StandardCharsets.UTF_8);
            String pyHash = c.get("hash").asText();
            assertTrue(pyHash.startsWith("$2b$10$"), c.get("name").asText());
            assertTrue(hasher.matches(password, pyHash), "Python hash must verify: " + c.get("name").asText());
            for (String bad : wrong) {
                assertFalse(hasher.matches(bad, pyHash), "wrong password accepted: " + c.get("name").asText());
            }
            String javaHash = hasher.hash(password);
            assertTrue(javaHash.startsWith("$2b$10$"), "new hash must be $2b$");
            assertTrue(hasher.matches(password, javaHash));
            for (String bad : wrong) {
                assertFalse(hasher.matches(bad, javaHash));
            }
            if (c.get("name").asText().equals("exactly-72-bytes")
                    || c.get("name").asText().equals("73-bytes-truncated-to-72")) {
                String p72 = "a".repeat(72);
                for (String equivalent : new String[]{p72, p72 + "b", p72 + "c"}) {
                    assertTrue(hasher.matches(equivalent, pyHash),
                            "72-byte truncation equivalence (py): " + c.get("name").asText());
                    assertTrue(hasher.matches(equivalent, javaHash),
                            "72-byte truncation equivalence (java): " + c.get("name").asText());
                }
            }
            javaCases.add(Map.of("name", c.get("name").asText(), "hash", javaHash));
        }
        Map<String, Object> out = Map.of("algorithm", "bcrypt", "variant", "$2b$", "rounds", 10, "cases", javaCases);
        Files.createDirectories(SERVER_DIR.resolve("target"));
        Files.writeString(SERVER_DIR.resolve("target/bcrypt-java-vectors.json"),
                JSON.writeValueAsString(out) + "\n", StandardCharsets.UTF_8);
    }

    @Test
    void rtV1PythonVectorsVerifyInJava() throws Exception {
        JsonNode doc = JSON.readTree(Files.readString(
                TOOLS_DIR.resolve("rt-v1/out/rt-v1-py-vectors.json")));
        byte[] secret = HexFormat.of().parseHex(doc.get("secret_hex").asText());
        String kid = doc.get("kid").asText();
        String aud = doc.get("audience").asText();
        for (JsonNode v : doc.get("vectors")) {
            RtV1VerifyResult result = RtV1Codec.verify(v.get("ticket").asText(), kid, secret, aud,
                    v.get("now").asLong());
            assertEquals(v.get("expect").asText(), result.reason(),
                    "vector " + v.get("name").asText());
        }
        RtV1VerifyResult valid = RtV1Codec.verify(
                doc.get("vectors").get(0).get("ticket").asText(), kid, secret, null,
                doc.get("vectors").get(0).get("now").asLong());
        assertTrue(valid.ok());
        assertEquals(UUID.fromString("22222222-2222-4222-8222-222222222222"), valid.body().sid());

        byte[] payload = ("{\"sid\":\"22222222-2222-4222-8222-222222222222\","
                + "\"uid\":\"11111111-1111-4111-8111-111111111111\","
                + "\"tid\":\"33333333-3333-4333-8333-333333333333\","
                + "\"mid\":\"44444444-4444-4444-8444-444444444444\","
                + "\"aud\":\"langgraph-runtime\",\"iat\":1760400000,\"exp\":1760400060,"
                + "\"crev\":7,\"urev\":0,\"trev\":5,\"mrev\":3,\"aud\":\"dup\"}").getBytes(StandardCharsets.UTF_8);
        RtV1Body body = new RtV1Body(
                UUID.fromString("22222222-2222-4222-8222-222222222222"),
                UUID.fromString("11111111-1111-4111-8111-111111111111"),
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                UUID.fromString("44444444-4444-4444-8444-444444444444"),
                "langgraph-runtime", 1760400000L, 1760400060L, 7L, 0L, 5L, 3L);
        String ticket = RtV1Codec.sign(body, kid, secret);
        assertEquals("ok", RtV1Codec.verify(ticket, kid, secret, aud, 1760400010L).reason());
        String[] segments = ticket.split("\\.");
        String payloadSegment = segments[0];
        char last = payloadSegment.charAt(payloadSegment.length() - 1);
        char flip = last == 'A' ? 'B' : 'A';
        segments[0] = payloadSegment.substring(0, payloadSegment.length() - 1) + flip;
        assertEquals("bad_signature",
                RtV1Codec.verify(String.join(".", segments), kid, secret, aud, 1760400010L).reason());

        String envelope = "{\"kid\":\"vector-1\",\"p\":"
                + new String(payload, StandardCharsets.UTF_8) + "}";
        String signingInput = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(envelope.getBytes(StandardCharsets.UTF_8));
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        String sig = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
        RtV1VerifyResult dup = RtV1Codec.verify(signingInput + "." + sig, kid, secret, aud, 1760400010L);
        assertEquals("malformed", dup.reason(), "duplicate aud must be rejected");

        writeJavaTokenDoc(body, kid, secret, aud, 1760400010L);
    }

    private void writeJavaTokenDoc(RtV1Body body, String kid, byte[] secret, String aud, long now)
            throws IOException {
        List<Map<String, Object>> vectors = new ArrayList<>();
        vectors.add(vector("valid", RtV1Codec.sign(body, kid, secret), now, "ok"));
        vectors.add(vector("wrong-audience",
                RtV1Codec.sign(new RtV1Body(body.sid(), body.uid(), body.tid(), body.mid(), "knowledge",
                        body.iat(), body.exp(), body.crev(), body.urev(), body.trev(), body.mrev()), kid, secret),
                now, "bad_audience"));
        vectors.add(vector("wrong-kid", RtV1Codec.sign(body, "other-kid", secret), now, "bad_kid"));
        vectors.add(vector("expired",
                RtV1Codec.sign(new RtV1Body(body.sid(), body.uid(), body.tid(), body.mid(), body.aud(),
                        100L, 160L, body.crev(), body.urev(), body.trev(), body.mrev()), kid, secret),
                1000L, "expired"));
        vectors.add(vector("wrong-secret-signature", RtV1Codec.sign(body, kid, new byte[32]), now,
                "bad_signature"));
        String good = RtV1Codec.sign(body, kid, secret);
        String suffix = good.substring(good.length() - 2);
        String replacement = suffix.equals("aa") ? "bb" : "aa";
        vectors.add(vector("mutated-signature", good.substring(0, good.length() - 2) + replacement, now,
                "bad_signature"));

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("kid", kid);
        doc.put("secret_hex", HexFormat.of().formatHex(secret));
        doc.put("audience", aud);
        doc.put("vectors", vectors);
        Files.createDirectories(SERVER_DIR.resolve("target"));
        Files.writeString(SERVER_DIR.resolve("target/rt-v1-java-tokens.json"),
                JSON.writeValueAsString(doc) + "\n", StandardCharsets.UTF_8);
    }

    private Map<String, Object> vector(String name, String ticket, long now, String expect) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("ticket", ticket);
        m.put("now", now);
        m.put("expect", expect);
        return m;
    }
}
