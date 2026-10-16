package com.airagent.iam.security.satoken;

import cn.dev33.satoken.stp.StpLogic;
import com.airagent.iam.security.token.OpaqueTokens;

/**
 * 把 Sa-Token 的 token-session Redis 键从"原始 token"改为"token 摘要"。
 *
 * <p>这样在仅持有数据库摘要（如 logout-all）时仍能构造并清理对应 Redis 键；
 * 原始令牌不出现在任何持久化位置。所有查找路径（create/getLoginId/last-active）
 * 都经过这两个拼接方法，行为对上层透明。
 */
public class DigestStpLogic extends StpLogic {

    public DigestStpLogic() {
        super("login");
    }

    @Override
    public String splicingKeyTokenValue(String tokenValue) {
        return super.splicingKeyTokenValue(OpaqueTokens.digest(tokenValue));
    }

    @Override
    public String splicingKeyLastActiveTime(String tokenValue) {
        return super.splicingKeyLastActiveTime(OpaqueTokens.digest(tokenValue));
    }

    /**
     * 仅有摘要时直接构造 Redis 键（用于 outbox 重放清理）；必须与令牌解析路径同构。
     * 直接调 super，避免本类 override 对入参再次求摘要。
     */
    public String keyByDigest(String digest) {
        return super.splicingKeyTokenValue(digest);
    }

    /**
     * 浏览器 /web-api 链路：句柄只映射到 session id，服务端从 PG 取该会话令牌摘要后，
     * 经与 {@code getLoginIdByToken} 同构的路径核验 Redis Sa-Token 存活性，
     * 原始令牌始终不经过浏览器也不落地句柄表。
     */
    public Object getLoginIdByDigest(String digest) {
        return getSaTokenDao().get(keyByDigest(digest));
    }

    /** 按摘要立即删除令牌 Redis 键与空闲续期键（登出即时清理；权威拒绝仍以 PG 为准）。 */
    public void deleteByDigest(String digest) {
        getSaTokenDao().delete(keyByDigest(digest));
        getSaTokenDao().delete(super.splicingKeyLastActiveTime(digest));
    }
}
