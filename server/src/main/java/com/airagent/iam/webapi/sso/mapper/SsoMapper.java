package com.airagent.iam.webapi.sso.mapper;

import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.entity.SsoRegistrationDO;
import com.airagent.iam.webapi.sso.entity.SsoStateDO;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 中央 SSO 的数据访问（Mapper 层，SQL 见 {@code mapper/webapi/sso/SsoMapper.xml}）。
 *
 * <p>分层位置：只被 {@link com.airagent.iam.webapi.sso.SsoClientAuthenticator}、
 * {@link com.airagent.iam.webapi.sso.service.impl.SsoAuthorizeServiceImpl} 与
 * {@link com.airagent.iam.webapi.sso.service.impl.SsoExchangeServiceImpl} 调用，
 * Controller 不直接使用。
 *
 * <p>访问方式：<em>每一条</em>语句都是 {@code SELECT ... FROM iam_auth.<函数>(...)} 形式的
 * SECURITY DEFINER 函数调用，没有任何裸表 SQL。原因：{@code iam.sso_clients}、
 * {@code iam.sso_states}、{@code iam.sso_tickets}（以及 {@code iam.browser_handles}）都
 * {@code ENABLE ROW LEVEL SECURITY} 且<em>不建任何策略</em>，请求角色 {@code iam_app} 直读直写
 * 一律为空/被拒，读写必须收敛到 V10/V11/V17 授予的函数上。函数只按单个键控参数做单行操作，
 * 且不返回 {@code secret_digest}（除 {@code sso_client_get} 外，而该列在 XML 里未被选取）。
 *
 * <p>缓存与事务：全部语句 {@code useCache="false"} 关闭二级缓存；写入与消费类语句额外
 * {@code affectData="true" flushCache="true"}，保证同一次请求内不会读到旧快照。
 * {@code saveState}/{@code saveTicket} 与审计写入需在同一 Spring 事务内先经
 * {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 建立上下文——
 * 上下文并非 state/ticket 函数所需（它们是 SECURITY DEFINER），而是 {@code iam.audit_logs}
 * 的 FORCE RLS 写策略要求。
 *
 * <p>时间口径：{@code expiresAt} 一律由服务层以 {@code OffsetDateTime.now(ZoneOffset.UTC)} 加
 * 配置 TTL 得出（{@code iam.sso.state-ttl-seconds} 缺省 600 秒、{@code iam.sso.ticket-ttl-seconds}
 * 缺省 30 秒），落 {@code timestamptz} 列；到期判定在数据库侧以 {@code expires_at > now()}
 * 做瞬时点比较，不受偏移量与本机时区影响。摘要入参均为
 * {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 得到的 64 位小写十六进制
 * SHA-256，原始 state/ticket/密钥从不进入本层以下。
 *
 * @author Acerola
 */
@Mapper
public interface SsoMapper {

    /**
     * Basic 凭据核验：按 {@code client_id + secret 摘要} 认证发起兑换的 SSO 客户端
     * （SQL 为 {@code iam_auth.authenticate_sso_client(#{clientId}, #{digest})}，见 V11）。
     *
     * <p>函数只在 {@code status = 'active'} 且摘要相等时返回行；不存在、密钥错误、已停用三种情况
     * 在函数内<em>合并</em>为同一 {@code RAISE EXCEPTION ... ERRCODE = '28000'}，因此调用方无法据此
     * 枚举客户端，映射后都是同一个 401。
     *
     * @param clientId Basic 中 {@code user-id} 段的客户端标识，长度上界由调用方校验为 128
     * @param digest 客户端密钥明文的 SHA-256 十六进制摘要；密钥明文<em>不</em>进入本层，
     *               也不与 {@code secret_digest} 列以外的任何值比较
     * @return 已认证的 {@link SsoClientView}（不含密钥列）；正常路径不会返回 {@code null}
     *         ——凭据不符以 28000 抛出，{@code null} 判定只是调用方的防御分支
     * @throws org.springframework.dao.DataAccessException 28000 凭据无效或客户端已停用，
     *                                                      由 {@link com.airagent.iam.web.error.PgErrorTranslator} 翻译
     */
    SsoClientView authenticate(@Param("clientId") String clientId, @Param("digest") String digest);

    /**
     * 读取授权跳转所需的注册信息（SQL 为 {@code iam_auth.sso_client_get(#{clientId})}，见 V10）。
     *
     * <p>授权链路在浏览器会话已核验之后调用，用于精确回调比对、Origin 白名单与状态判定。
     * 函数按主键取行、不筛状态，停用客户端同样返回一行，由服务层判 {@code status} 后拒绝。
     *
     * @param clientId 客户端标识；{@code null} 或空白由服务层先行拒绝，不会到达本层
     * @return 注册信息（不含任何密钥列）；客户端不存在时返回 {@code null}
     */
    SsoRegistrationDO selectClient(@Param("clientId") String clientId);

    /**
     * 登记一次性 {@code state}（SQL 为 {@code iam_auth.sso_state_save(...)}，写 {@code iam.sso_states}，见 V10）。
     *
     * <p>{@code state} 由消费方生成、服务端只存其摘要，因此"原始值 → 回调 query → 兑换请求体"
     * 这条链路与库内表示完全分离。行内绑定发起授权时的浏览器会话句柄摘要与精确回调，
     * 供 {@link #consumeState} 原子领取时回读。
     *
     * @param digest      原始 state 的 SHA-256 十六进制摘要，作为主键；重复登记会撞主键并抛异常
     * @param clientId    发起授权的客户端标识，兑换时用于绑定校验
     * @param handleDigest 当前浏览器会话句柄摘要（{@code iam.browser_handles.handle_digest} 同口径）；
     *                     列 NOT NULL，登记后不参与兑换判定
     * @param callbackUrl 本次授权的回调地址，必须与注册值精确相等（服务层已先比对才落库）
     * @param expiresAt   到期时刻；服务层按 {@code iam.sso.state-ttl-seconds}（缺省 600 秒）
     *                    自 UTC now 起算，数据库侧以瞬时点比较
     * @return 恒为 1（{@code SELECT 1 FROM ...} 包装 void 函数）；写入失败以异常抛出
     */
    int saveState(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("handleDigest") String handleDigest,
            @Param("callbackUrl") String callbackUrl,
            @Param("expiresAt") OffsetDateTime expiresAt);

    /**
     * 登记一次性 {@code ticket}（SQL 为 {@code iam_auth.sso_ticket_save(...)}，写 {@code iam.sso_tickets}，见 V10）。
     *
     * <p>ticket 是授权成功时随 303 回调下发给消费方的<em>人类会话代表</em>：行内直接绑定当前
     * 浏览器中央会话 id，兑换时凭此取回源会话，因此 ticket 原始值本身不含任何身份信息。
     * 它与 {@code state} 各自独立成行、各自原子消费——state 证明"回调匹配发起方"，
     * ticket 证明"哪个中央会话授权了这次兑换"。
     *
     * @param digest      原始 ticket 的 SHA-256 十六进制摘要，作为主键；原始值只在回调 query 出现一次
     * @param clientId    被授权的客户端标识，兑换时与凭据身份共同构成领取条件
     * @param sessionId   浏览器中央会话 id（{@code iam.auth_sessions.id}，外键约束）；
     *                    兑换出的派生会话经 {@code central_session_id} 挂到它所属的中央会话下
     * @param callbackUrl 授权时校验通过的精确回调地址，兑换时必须逐字重复
     * @param expiresAt   到期时刻；服务层按 {@code iam.sso.ticket-ttl-seconds}（缺省 30 秒）
     *                    自 UTC now 起算
     * @return 恒为 1（void 函数的 {@code SELECT 1} 包装）；写入失败以异常抛出
     */
    int saveTicket(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("sessionId") UUID sessionId,
            @Param("callbackUrl") String callbackUrl,
            @Param("expiresAt") OffsetDateTime expiresAt);

    /**
     * 原子领取 {@code ticket}（SQL 为 {@code iam_auth.sso_ticket_consume(...)}，见 V10）。
     *
     * <p>单条 {@code UPDATE ... SET consumed_at = now() WHERE ticket_digest = ? AND client_id = ?
     * AND redirect_uri = ? AND consumed_at IS NULL AND expires_at > now() RETURNING session_id}：
     * "校验—置位—取回"在同一语句内完成，天然防重放——并发或二次兑换的第二个事务命中 0 行。
     * 三个 WHERE 条件是<em>合取</em>的：客户端不符或回调不逐字相等都按"无效"处理，与过期/已用同一结果。
     *
     * @param digest      请求体 ticket 的 SHA-256 摘要；不匹配任何主键即 0 行
     * @param clientId    已认证客户端标识（来自凭据核验结果，不接受请求体自述）
     * @param callbackUrl 请求体的 {@code redirect_uri}，与登记值精确比对
     * @return 该 ticket 绑定的中央会话 id；返回 {@code null} 表示不存在、客户端或回调不符、
     *         已过期或已被消费——四种情形对调用方不可区分，统一 401
     */
    UUID consumeTicket(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("callbackUrl") String callbackUrl);

    /**
     * 原子领取 {@code state}（SQL 为 {@code iam_auth.sso_state_consume(#{digest})}，见 V10）。
     *
     * <p>与 {@link #consumeTicket} 同一套语义：单条 UPDATE 以 {@code consumed_at IS NULL AND
     * expires_at > now()} 为条件置位并 RETURNING，重放或过期命中 0 行。领取条件<em>只</em>含摘要
     * 与有效性，不含客户端与回调——两者由调用方在拿到返回值后比对，不符则整体回滚。
     *
     * @param digest 请求体 state 的 SHA-256 摘要
     * @return 登记的客户端标识与精确回调（函数另返回 {@code handle_digest}，XML 未映射）；
     *         返回 {@code null} 表示 state 不存在、已过期或已被使用
     */
    SsoStateDO consumeState(@Param("digest") String digest);

    /**
     * Bearer 客户端密钥核验：只按密钥摘要反查 SSO 客户端
     * （SQL 为 {@code iam_auth.authenticate_sso_bearer(#{digest})}，见 V17）。
     *
     * <p>与 {@link #authenticate} 的区别是不提供 {@code clientId}：身份完全由摘要决定。函数额外要求
     * 该摘要在全表<em>只命中一行</em>（{@code count(*) = 1} 子查询），因此两个客户端共用同一密钥时
     * 谁都无法认证——返回 0 行而不是任选其一，避免凭据歧义。同样只放行 {@code status = 'active'}。
     *
     * @param digest Bearer 凭据（客户端密钥明文）的 SHA-256 十六进制摘要；原始凭据不进入本层
     * @return 唯一命中的 {@link SsoClientView}；无匹配、摘要被多个客户端共享或客户端停用都返回
     *         {@code null}（本函数以空结果而非 28000 表达失败），由调用方统一映射 401
     */
    SsoClientView authenticateBearer(@Param("digest") String digest);
}
