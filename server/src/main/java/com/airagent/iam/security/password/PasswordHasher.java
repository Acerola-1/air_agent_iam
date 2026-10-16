package com.airagent.iam.security.password;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

/**
 * 口令哈希组件，固定 $2b$ / cost 10。
 *
 * <p>口令按 UTF-8 字节参与 bcrypt，超过 72 字节的部分与 Python bcrypt 一样被截断后再哈希/校验，
 * 因此对历史 $2a$/$2b$/$2y$ 哈希的校验结果与 Python bcrypt 4.x 一致。
 */
@Component
public class PasswordHasher {

    private static final int STRENGTH = 10;
    private static final String VERSION = "$2b$";
    private static final int MAX_BCRYPT_BYTES = 72;
    private final SecureRandom secureRandom;

    public PasswordHasher() {
        try {
            this.secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("strong SecureRandom unavailable", e);
        }
    }

    /** 管理建档/重置与登录一致的口令形状：8–256 字符（bcrypt 仍按 72 字节截断参与运算）。 */
    public void validateStrength(String rawPassword) {
        if (rawPassword == null || rawPassword.length() < 8 || rawPassword.length() > 256) {
            throw com.airagent.iam.web.error.ApiException.badRequest("password 长度必须在 8 到 256 之间");
        }
    }

    public String hash(String rawPassword) {
        String salt = BCrypt.gensalt(VERSION, STRENGTH, secureRandom);
        return BCrypt.hashpw(truncate(rawPassword), salt);
    }

    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return BCrypt.checkpw(truncate(rawPassword), storedHash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private byte[] truncate(String rawPassword) {
        byte[] bytes = rawPassword.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_BCRYPT_BYTES) {
            return bytes;
        }
        byte[] truncated = new byte[MAX_BCRYPT_BYTES];
        System.arraycopy(bytes, 0, truncated, 0, MAX_BCRYPT_BYTES);
        return truncated;
    }
}
