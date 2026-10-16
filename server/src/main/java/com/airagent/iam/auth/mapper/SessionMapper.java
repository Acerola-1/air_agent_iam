package com.airagent.iam.auth.mapper;

import com.airagent.iam.auth.entity.LoginUserDO;
import com.airagent.iam.auth.entity.SessionContextDO;
import com.airagent.iam.auth.entity.SessionTimerDO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 人类会话与登录权威的数据访问（Mapper 层，SQL 见 mapper/auth/SessionMapper.xml）。
 *
 * <p>运行在 iam_app 请求角色下：会话状态机、口令写入与权威快照一律经
 * {@code iam_auth.*} 的 SECURITY DEFINER 函数完成，本层不直接 UPDATE 权威表。
 * 全部语句关闭二级缓存（{@code useCache="false"}）、状态变更语句
 * {@code flushCache="true"}，配合全局 {@code local-cache-scope=STATEMENT}，
 * 保证同一请求内不会读到过期快照——授权判定不存在跨请求正向缓存。
 *
 * <p>约定：函数内 {@code RAISE} 的 SQLSTATE 由
 * {@link com.airagent.iam.web.error.PgErrorTranslator} 统一翻译（28000/28P01→401、
 * P0010→409、P0012→403、23514→409、连接/取消类如 08 类与 57P01→503），调用方按此裁决 HTTP 语义。
 * 涉及 RLS 表的直读查询（如企业列表）必须在同一事务内先经
 * {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 设置请求上下文。
 *
 * @author Acerola
 */
@Mapper
public interface SessionMapper {

    /**
     * 按域与账号取登录核验行（{@code iam_auth.find_user_for_login}，SECURITY DEFINER）。
     *
     * <p>口令摘要只能经该函数取得：iam_app 对 {@code iam.users.password_hash} 无直读权限。
     * 停用账号同样会返回，由调用方与口令校验折叠为同一个 401。
     *
     * @param realm   账号域，当前仅 {@code workforce}
     * @param account 登录账号原文，等值匹配（不做模糊或大小写折叠）
     * @return 账号行；同域下账号不存在时返回 {@code null}
     */
    LoginUserDO findLogin(@Param("realm") String realm, @Param("account") String account);

    /**
     * 建立新会话（登录成功后与审计同事务调用）。
     *
     * <p>写入 {@code current_tenant_id = NULL}、{@code ctx_version = 1}、{@code status = active}，
     * 并把登录时刻的 {@code users.auth_revision} 冻结为 {@code base_user_revision}；
     * {@code expires_at} 与 {@code idle_expires_at} 取 {@code now + LEAST(idle, absolute)}，
     * {@code absolute_expires_at} 取 {@code now + absolute}。企业基线（tenant/membership）留待切企业时写入。
     *
     * @param userId          会话主体用户 UUID；用户不存在时函数以 SQLSTATE 28000 报错
     * @param realm           账号域，写入 auth_sessions.realm
     * @param audience        登录受众，写入 login_audience
     * @param digest          访问令牌的 SHA-256 摘要（列上有唯一约束）；原始令牌不进入本层
     * @param idleSeconds     空闲时限，单位秒
     * @param absoluteSeconds 绝对时限，单位秒
     * @return 新会话 id
     */
    UUID createSession(
            @Param("userId") UUID userId,
            @Param("realm") String realm,
            @Param("audience") String audience,
            @Param("digest") String digest,
            @Param("idleSeconds") long idleSeconds,
            @Param("absoluteSeconds") long absoluteSeconds);

    /**
     * 经 SSO 兑换为同一人类签发独立应用会话（{@code iam_auth.mint_sso_session}）。
     *
     * <p>目标为源会话所属的中央会话（{@code COALESCE(central_session_id, id)}）并持其行锁：
     * 中央会话已撤销或已过任一截止时间时以 SQLSTATE 28000 报错，受众不在白名单内以 23514 报错。
     * 新会话复制中央会话的 {@code current_tenant_id}、{@code ctx_version} 与三项授权基线，
     * 时限取"自身窗口"与"中央会话剩余时间"的较小值，因此子会话绝不比中央会话活得更久。
     *
     * @param sourceId        源会话 id（浏览器中央会话或其子会话），用于定位中央会话
     * @param audience        目标受众，仅 {@code air-agent} / {@code knowledge} / {@code iam-admin}
     * @param digest          新访问令牌的 SHA-256 摘要
     * @param idleSeconds     空闲时限，单位秒
     * @param absoluteSeconds 绝对时限，单位秒
     * @return 新会话 id
     */
    UUID mintSsoSession(
            @Param("sourceId") UUID sourceId,
            @Param("audience") String audience,
            @Param("digest") String digest,
            @Param("idleSeconds") long idleSeconds,
            @Param("absoluteSeconds") long absoluteSeconds);

    /**
     * 撤销单个会话（{@code iam_auth.revoke_session}），置 {@code status = revoked} 并写
     * {@code revoked_at / revoke_reason}。
     *
     * @param sessionId 会话 UUID
     * @param reason    撤销原因码，写入 revoke_reason 审计列（如 {@code user.logout}）
     * @return 被撤销会话的令牌摘要；会话不存在或已非 active 时返回 {@code null}（此时无需清理 Redis）
     */
    String revokeSession(@Param("sessionId") UUID sessionId, @Param("reason") String reason);

    /**
     * 撤销某用户全部活跃会话并额外推进其授权代次（{@code iam_auth.revoke_user_sessions}，
     * {@code p_keep} 传 {@code null}）。
     *
     * <p>全撤包含调用者自身的当前会话——全局登出与本人改密都会立即使本次登录失效。
     * 代次 +1 使任何仍存活的旧快照在下一次权威核验时被拒，Redis 键删除由调用方把摘要写入同事务 outbox。
     *
     * @param userId 用户 UUID
     * @param reason 撤销原因码（如 {@code user.logout_all} / {@code user.password_change}）
     * @return 被撤销会话的令牌摘要列表；无活跃会话时为空列表
     */
    List<String> revokeUserSessions(@Param("userId") UUID userId, @Param("reason") String reason);

    /**
     * 列出该用户当前可切入的企业（直读 {@code iam.tenants} 联 {@code iam.tenant_memberships}）。
     *
     * <p>SQL 已过滤"成员关系 active 且企业 active"，按企业 code 升序；{@code is_owner} 列实际表达
     * "该成员关系是否持有活跃 tenant_admin 角色"。两表均为 FORCE RLS，调用前必须把
     * {@code app.user_id} 设为该用户、平台标志关闭，否则结果为空。
     *
     * @param userId 用户 UUID
     * @return 企业概览列表；无可切换企业时为空列表
     */
    List<TenantMembershipVO> selectTenants(@Param("userId") UUID userId);

    /**
     * CAS 切换当前企业（{@code iam_auth.switch_session_context}）。
     *
     * <p>作用于中央会话并持其行锁：会话已撤销/过期以 28000 报错，
     * {@code ctx_version} 与期望值不符以 P0010 报错（并发切换或已在他处切过），
     * 目标企业非活跃或该用户非其活跃成员以 P0012 报错。成功时 {@code ctx_version +1}、
     * 刷新企业/成员两项基线，并由 {@code auth_sessions_synchronize_central} 触发器把新上下文
     * 与纪元传播到同一中央会话下的全部子会话。
     *
     * @param sessionId       会话 UUID（子会话亦可，函数自行定位中央会话）
     * @param tenantId        目标企业 UUID
     * @param expectedVersion 期望的会话上下文代次，取自当前身份视图
     * @return 切换后的会话 id（即中央会话 id）
     */
    UUID switchContext(
            @Param("sessionId") UUID sessionId,
            @Param("tenantId") UUID tenantId,
            @Param("expectedVersion") long expectedVersion);

    /**
     * 显式续期空闲窗口（{@code iam_auth.renew_session}）。
     *
     * <p>会话不存在以 28000 报错；已撤销或已过绝对/空闲任一截止时间同样以 28000 报错——
     * 过期会话不可复活；纪元不符以 P0010 报错。新空闲截止时刻在持锁后取
     * {@code GREATEST(原 idle_expires_at, clock_timestamp + idleSeconds)} 再被
     * {@code absolute_expires_at} 夹住，因此只增不减、绝不延长绝对上限。
     *
     * @param sessionId       会话 UUID（子会话亦可，函数续期中央会话）
     * @param expectedVersion 期望的会话上下文代次
     * @param idleSeconds     本次续期的空闲增量，单位秒（配置 {@code iam.session.renew-idle-seconds}）
     * @return 续期后的绝对与空闲到期时刻
     */
    SessionTimerDO renew(
            @Param("sessionId") UUID sessionId,
            @Param("expectedVersion") long expectedVersion,
            @Param("idleSeconds") long idleSeconds);

    /**
     * 经 SECURITY DEFINER 函数 {@code iam_auth.set_user_password} 写入新口令摘要。
     *
     * <p>iam_app 无 password_hash 列直写权限，必须走该函数；口令变化触发
     * {@code users_bump_auth_revision} 使授权代次 +1。用户不存在时函数以 SQLSTATE P0002
     * 报错（该状态未定义专门映射，最终按内部错误处理），调用方须先确认账号存在。
     *
     * @param userId        用户 UUID
     * @param passwordHash  BCrypt 摘要（明文口令不进入本层）
     * @return 写入后的授权代次
     */
    long setPassword(@Param("userId") UUID userId, @Param("passwordHash") String passwordHash);

    /**
     * 按会话 id 取令牌摘要（{@code iam_auth.session_token_digest}），供仅持有会话 id 的
     * 浏览器链路构造并清理 Redis 键。
     *
     * <p>函数不过滤会话状态：已撤销/已过期的会话同样返回摘要，以便撤销后仍能完成清理。
     * 摘要属服务端内部数据，不得出现在任何响应体中。
     *
     * @param sessionId 会话 UUID
     * @return 令牌摘要；会话 id 不存在时返回 {@code null}
     */
    String selectTokenDigest(@Param("sessionId") UUID sessionId);

    /**
     * 按令牌摘要反查会话主体与当前企业（{@code iam_auth.find_session_by_digest}）。
     *
     * <p>auth_sessions 受 RLS 保护，无请求上下文时只能经该 SECURITY DEFINER 函数读取。
     * 该结果不含状态、时限与授权代次，不能用于放行判断。
     *
     * @param digest 令牌摘要
     * @return 会话主体与当前企业；摘要无对应会话时返回 {@code null}
     */
    SessionContextDO findContext(@Param("digest") String digest);

    /**
     * 单次主库往返加载权威快照 jsonb 文本（{@code iam_auth.load_trusted_authority_snapshot}，V18）。
     *
     * <p>函数在同一语句内先按摘要定位会话、据此推导并设置可信 RLS 上下文，再调用
     * {@code iam_auth.load_authority_snapshot} 汇总会话/账号/企业/成员关系、四类代次、
     * 平台与企业角色及权限码，最后恢复调用方原有上下文——因此调用方无需预先设置上下文，
     * 也不会污染调用方事务的上下文。判定结论（{@code status}）由数据库给出：授权代次高于会话基线、
     * 会话过期或撤销都体现为不可用状态。
     *
     * @param digest 令牌摘要
     * @return jsonb 文本；摘要无对应会话时为仅含 {@code {"status":"missing"}} 的 JSON 文本，
     *         不返回 {@code null}
     */
    String loadSnapshotJson(@Param("digest") String digest);
}
