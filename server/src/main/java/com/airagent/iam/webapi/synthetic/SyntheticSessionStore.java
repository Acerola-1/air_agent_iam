package com.airagent.iam.webapi.synthetic;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 合成 BFF 的服务端会话存储（内部组件，仅本机验收用，无 HTTP 入口）。
 *
 * <p>分层位置：被 {@link com.airagent.iam.webapi.synthetic.controller.SyntheticBffController}
 * 独占，用来演示真实跨端 SSO 中"BFF 持有应用令牌、浏览器只见 BFF 自己的会话 cookie"的隔离边界——
 * SSO 兑换得到的人类应用访问令牌只保存在本进程内存里，JS/URL/响应都不可见。
 *
 * <p>非持久与单实例语义：进程重启即清空，键空间为进程内 {@link ConcurrentHashMap}，
 * <em>不</em>跨节点共享、<em>不</em>做后台清扫；过期条目在 {@link #get} 命中时惰性删除。
 * 真实 BFF 应替换为受控的服务端存储（带 TTL、持久化与多实例一致性）。这里不承载任何
 * 权威判定，中央会话的撤销/续期由 IAM 侧数据库触发器与 {@code /v1/auth/me} 调用体现。
 *
 * @author Acerola
 */
@Component
public class SyntheticSessionStore {

    /**
     * 一条合成 BFF 会话（值对象，仅本存储使用）。
     *
     * @param clientKey    合成客户端 key（对应 {@code iam.sso.clients} 的键）
     * @param accessToken  SSO 兑换得到的人类应用访问令牌；只在服务端内存持有，绝不下发到浏览器
     * @param identityJson 兑换响应里的身份 JSON 原文（{@code tools.jackson} 序列化文本）；
     *                     当前 BFF 实现实际每次实时回源 {@code /v1/auth/me}，此字段仅作演示留存
     * @param expiresAt    本地过期时刻（{@code Instant}），由 BFF 按 {@code expires_in} 减 30 秒
     *                     缓冲计算，最小 60 秒；到点由 {@link #get(String)} 惰性剔除
     * @author Acerola
     */
    public record Entry(String clientKey, String accessToken, String identityJson,
                        Instant expiresAt) {
        /**
         * 条目是否已到期（{@code now >= expiresAt}）。
         *
         * @return 到期返回 {@code true}
         */
        boolean expired() {
            return !Instant.now().isBefore(expiresAt);
        }
    }

    /** 按客户端 key 隔离的 BFF 会话表。 */
    private final ConcurrentHashMap<String, Entry> sessions = new ConcurrentHashMap<>();

    /**
     * 写入/覆盖一条 BFF 会话。
     *
     * @param bffSessionId 浏览器侧 HttpOnly Cookie 携带的随机会话标识；调用方保证非空
     * @param entry        会话内容
     */
    public void put(String bffSessionId, Entry entry) {
        sessions.put(bffSessionId, entry);
    }

    /**
     * 读取会话；命中但已到期则就地删除并视为未命中。
     *
     * @param bffSessionId 会话标识；{@code null} 视为未命中
     * @return 未过期的 {@link Entry}；标识缺失、无对应条目或已过期时返回 {@code null}
     */
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

    /**
     * 删除会话（登出或兑换/回源失败时清理）。
     *
     * @param bffSessionId 会话标识；{@code null} 时静默不操作
     */
    public void remove(String bffSessionId) {
        if (bffSessionId != null) {
            sessions.remove(bffSessionId);
        }
    }
}
