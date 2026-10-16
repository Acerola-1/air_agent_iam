package com.airagent.iam.webapi.synthetic;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 合成 BFF 的服务端会话存储（仅本机验收用）：浏览器只持有随机会话 cookie，
 * 兑换得到的人类应用令牌只保存在这里，JS/URL 不可见。进程重启即清空，
 * 真实 BFF 应替换为受控的服务端存储。
 */
@Component
public class SyntheticSessionStore {

    public record Entry(String clientKey, String accessToken, String identityJson,
                        Instant expiresAt) {
        boolean expired() {
            return !Instant.now().isBefore(expiresAt);
        }
    }

    private final ConcurrentHashMap<String, Entry> sessions = new ConcurrentHashMap<>();

    public void put(String bffSessionId, Entry entry) {
        sessions.put(bffSessionId, entry);
    }

    public Entry get(String bffSessionId) {
        if (bffSessionId == null) {
            return null;
        }
        Entry entry = sessions.get(bffSessionId);
        if (entry == null) {
            return null;
        }
        if (entry.expired()) {
            sessions.remove(bffSessionId);
            return null;
        }
        return entry;
    }

    public void remove(String bffSessionId) {
        if (bffSessionId != null) {
            sessions.remove(bffSessionId);
        }
    }
}
