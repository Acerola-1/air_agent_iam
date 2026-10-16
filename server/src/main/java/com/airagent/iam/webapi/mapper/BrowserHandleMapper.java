package com.airagent.iam.webapi.mapper;

import com.airagent.iam.webapi.BrowserHandleRow;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * iam.browser_handles 数据访问（Mapper 层，SQL 见
 * {@code resources/mapper/webapi/BrowserHandleMapper.xml}）。
 *
 * <p>运行在 iam_app 请求角色下：{@code browser_handles} 表已 {@code ENABLE RLS} 且<em>无</em>
 * policy，默认拒绝对 iam_app 直读直写（V1 建表 + V10 授予），所有操作都收敛到
 * {@code iam_auth.browser_handle_*} 的 SECURITY DEFINER 函数；本 XML 用
 * {@code SELECT ... FROM iam_auth.xxx(...)} 包装函数调用以满足 MyBatis 语句形态。
 *
 * <p>缓存与写路径：所有<em>函数调用</em>写操作 {@code flushCache="true"} 并显式关闭二级缓存，
 * {@code resolve} 亦 {@code useCache="false"}——每次 {@code /web-api} 请求都要按句柄
 * 重新读取以即时看到登录绑定/吊销/滑动 TTL 后的最新状态，句柄读不存在任何"跨请求可复用快照"。
 *
 * <p>关键边界：原始句柄不出现在数据库与 Redis 键空间；调用方（{@link com.airagent.iam.webapi.service.BrowserSessionService}）
 * 只把 {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 的 SHA-256 摘要
 * 传入本层，本层也不返回任何原始令牌或口令。函数按 V10 授予仅允许 iam_app 执行。
 *
 * @author Acerola
 */
@Mapper
public interface BrowserHandleMapper {

    /**
     * 开户匿名句柄：以 {@code session_id = NULL} 插入 iam.browser_handles。
     *
     * <p>对应 {@code iam_auth.browser_handle_open(text, text, timestamptz)}；仅用于
     * 拿到 CSRF 与后续登录的锚点，不构成任何授权。
     *
     * @param digest    原始句柄的 SHA-256 十六进制摘要（主键，须全局唯一）
     * @param csrfToken 与该句柄绑定的双提交 CSRF 令牌
     * @param expiresAt 句柄到期时刻（{@code now + iam.web.handle-ttl-seconds}），UTC 时刻
     * @return SQL 包装值，函数成功执行恒为 1（无业务含义，异常路径直接抛出）
     */
    int open(
            @Param("digest") String digest,
            @Param("csrfToken") String csrfToken,
            @Param("expiresAt") OffsetDateTime expiresAt);

    /**
     * 登录成功绑定（会话固定防护）：同一事务内原子吊销旧匿名句柄 + 插入绑定真实会话的新句柄。
     *
     * <p>对应 {@code iam_auth.browser_handle_bind(text, text, uuid, text, timestamptz)}；
     * 新句柄 {@code authenticated_at} 由函数写入 now()。旧句柄缺失（Cookie 已过期或未走过
     * CSRF 端点）时 {@code oldDigest} 传 {@code null}，绑定仍成功、不影响登录成立。
     *
     * @param oldDigest 旧匿名句柄摘要；{@code null} 表示无可吊销的旧句柄
     * @param newDigest 新句柄摘要（主键，须与 oldDigest 不同）
     * @param sessionId 已建立的 {@code iam.auth_sessions.id}，浏览器后续经它做双检
     * @param csrfToken 与新句柄绑定的双提交 CSRF（登录响应会同时下发新 Cookie）
     * @param expiresAt 新句柄到期时刻，UTC
     * @return SQL 包装值，函数成功执行恒为 1
     */
    int bind(
            @Param("oldDigest") String oldDigest,
            @Param("newDigest") String newDigest,
            @Param("sessionId") UUID sessionId,
            @Param("csrfToken") String csrfToken,
            @Param("expiresAt") OffsetDateTime expiresAt);

    /**
     * 按摘要读取句柄行（无行锁）。
     *
     * <p>对应 {@code iam_auth.browser_handle_get(text)}；关闭二级缓存以保证每次读取
     * 都反映最新绑定/吊销/TTL 状态。
     *
     * @param digest 原始句柄的 SHA-256 摘要；{@code null} 或空白由服务层先行拒绝，
     *               本层不做防御
     * @return 命中的 {@link BrowserHandleRow}；句柄不存在（伪造或从未签发）时返回 {@code null}
     */
    BrowserHandleRow resolve(@Param("digest") String digest);

    /**
     * 滑动句柄 TTL：仅对未吊销行更新 {@code expires_at}。
     *
     * <p>对应 {@code iam_auth.browser_handle_touch(text, timestamptz)}；WHERE 已限定
     * {@code revoked_at IS NULL}，已吊销句柄静默不更新。
     *
     * @param digest    待刷新的句柄摘要
     * @param expiresAt 新的到期时刻（{@code now + iam.web.handle-ttl-seconds}），UTC
     * @return SQL 包装值，函数成功执行恒为 1；命中行数为 0 不通过返回值区分，
     *         调用方如需精确判定应自行以 {@link #resolve} 读回
     */
    int touch(@Param("digest") String digest, @Param("expiresAt") OffsetDateTime expiresAt);

    /**
     * 主动吊销句柄（登出/匿名句柄被替换等场景）。
     *
     * <p>对应 {@code iam_auth.browser_handle_revoke(text)}；仅当存在且未吊销时置
     * {@code revoked_at = now()} 并返回其 {@code session_id}。已吊销或不存在返回 {@code null}，
     * 使吊销天然幂等。
     *
     * @param digest 待吊销句柄的 SHA-256 摘要
     * @return 被吊销句柄所绑定的会话 id；匿名句柄或已吊销/不存在时为 {@code null}。
     *         调用方（{@link com.airagent.iam.webapi.controller.WebApiAuthController}）
     *         仅用返回值做审计参考，权威会话撤销仍由
     *         {@link com.airagent.iam.auth.service.SessionService#logout(com.airagent.iam.auth.CurrentSession)}
     *         独立完成
     */
    UUID revoke(@Param("digest") String digest);
}
