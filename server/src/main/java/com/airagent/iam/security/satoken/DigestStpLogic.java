package com.airagent.iam.security.satoken;

import cn.dev33.satoken.stp.StpLogic;
import com.airagent.iam.security.token.OpaqueTokens;

/**
 * Sa-Token 会话键的摘要化实现：把 Redis 里"原始 token 作键"改为"token 的 SHA-256 摘要作键"。
 *
 * <p>装配位置：由 {@link com.airagent.iam.config.SaTokenConfiguration} 在 {@code @PostConstruct}
 * 阶段以 {@code StpUtil.setStpLogic(new DigestStpLogic())} 全局替换默认逻辑，早于任何登录与校验调用，
 * 因此不存在两种键构形并存的窗口。登录类型固定为 {@code "login"}，令牌名取配置
 * {@code sa-token.token-name=Authorization}（仅从请求头读取，不读 Cookie/body）。
 *
 * <p>键构形（{@link #splicingKeyTokenValue(String)} 与 {@link #splicingKeyLastActiveTime(String)}
 * 只是在父类拼接前把入参换成摘要，其余结构与 Sa-Token 默认完全一致）：
 * <ul>
 *   <li>token → 登录主体映射键：{@code Authorization:login:token:<sha256-hex(rawToken)>}</li>
 *   <li>空闲续期时间戳键：{@code Authorization:login:last-active:<sha256-hex(rawToken)>}</li>
 * </ul>
 * 上层所有读写路径都收敛到这两个拼接方法（建会话写映射、按 token 取登录主体、按 token 删除、
 * 空闲冻结时间戳），所以替换对业务代码透明，浏览器/调用方拿到的仍是原始令牌，
 * 只有落到存储的表示被摘要化。
 *
 * <p>为什么存摘要而不是原文：会话在 PostgreSQL 侧的唯一持久化表示就是令牌摘要
 * （{@code iam.auth_sessions.token_digest}）。若 Redis 键用原文，则任何只有摘要的清理路径
 * （全局登出、管理员重置、outbox 重放）都无法构造出正确的键，撤销会留下清不掉的残留会话；
 * 反之键用摘要后，"从数据库摘要出发"与"从请求原文出发"两条路径落在同一个键上，
 * 既能核验也能清理。同时 Redis 内容泄露不再等于可重放的凭据泄露——摘要不可逆推原文，
 * 原始令牌自始至终不出现在数据库、Redis 键、日志与审计里。
 *
 * @author Acerola
 */
public class DigestStpLogic extends StpLogic {

    /**
     * 构造摘要化逻辑，登录类型标识固定为 {@code login}（参与键构形的第二段）。
     */
    public DigestStpLogic() {
        super("login");
    }

    /**
     * 令牌 → token 映射键的拼接：对入参令牌取 SHA-256 十六进制摘要后交给父类。
     *
     * @param tokenValue 原始访问令牌（非摘要）；{@code null} 时由摘要计算抛空指针，
     *                   调用方（Sa-Token 内部路径）保证非空
     * @return 形如 {@code Authorization:login:token:<64 位小写十六进制>} 的完整 Redis 键名
     */
    @Override
    public String splicingKeyTokenValue(String tokenValue) {
        return super.splicingKeyTokenValue(OpaqueTokens.digest(tokenValue));
    }

    /**
     * 令牌 → 空闲续期时间戳键的拼接，摘要口径与 {@link #splicingKeyTokenValue(String)} 一致。
     *
     * @param tokenValue 原始访问令牌（非摘要）
     * @return 形如 {@code Authorization:login:last-active:<64 位小写十六进制>} 的完整 Redis 键名
     */
    @Override
    public String splicingKeyLastActiveTime(String tokenValue) {
        return super.splicingKeyLastActiveTime(OpaqueTokens.digest(tokenValue));
    }

    /**
     * 仅有摘要时直接构造 Redis 键（用于 outbox 重放清理与管理侧批量撤销）；必须与令牌解析路径同构。
     *
     * <p>这里刻意直接调 {@code super}：本类的 override 会对入参再次求摘要，
     * 若传入已摘要的值就会得到"摘要的摘要"、删不到真实键。
     *
     * @param digest 令牌摘要（64 位小写十六进制），即 {@code iam.auth_sessions.token_digest} 的取值
     * @return 完整 Redis 键名，与 {@link #splicingKeyTokenValue(String)} 对同一会话的输出逐字符相同
     */
    public String keyByDigest(String digest) {
        return super.splicingKeyTokenValue(digest);
    }

    /**
     * 浏览器 /web-api 链路：句柄只映射到 session id，服务端从 PG 取该会话令牌摘要后，
     * 经与 {@code getLoginIdByToken} 同构的路径核验 Redis Sa-Token 存活性，
     * 原始令牌始终不经过浏览器也不落地句柄表。
     *
     * <p>读取的是 token→loginId 映射值本身：键不存在（会话已撤销、已过期或从未建立）返回
     * {@code null}。与父类 {@code getLoginIdByToken} 的差别仅在于本方法不附加空闲冻结判定，
     * 而本服务配置 {@code sa-token.active-timeout=-1}（不启用空闲冻结），两条路径结论一致。
     *
     * @param digest 令牌摘要（64 位小写十六进制），非空
     * @return 该令牌对应的登录主体（字符串形式的用户 id）；键不存在时返回 {@code null}
     */
    public Object getLoginIdByDigest(String digest) {
        return getSaTokenDao().get(keyByDigest(digest));
    }

    /**
     * 按摘要立即删除令牌 Redis 键与空闲续期键（登出即时清理；权威拒绝仍以 PG 为准）。
     *
     * <p>只清这两个令牌级键，不触碰账号级会话键——Redis 只是存活索引，残留不影响权威判定，
     * 删除失败或延迟由 outbox 重放兜底。两次删除都是幂等的键删除，键不存在时无副作用。
     *
     * @param digest 令牌摘要（64 位小写十六进制），非空
     */
    public void deleteByDigest(String digest) {
        getSaTokenDao().delete(keyByDigest(digest));
        getSaTokenDao().delete(super.splicingKeyLastActiveTime(digest));
    }
}
