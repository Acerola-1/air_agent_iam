package com.airagent.iam.webapi.sso.service.impl;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;
import com.airagent.iam.webapi.sso.entity.SsoStateDO;
import com.airagent.iam.webapi.sso.mapper.SsoMapper;
import com.airagent.iam.webapi.sso.service.SsoExchangeService;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * SSO 一次性 ticket 兑换的实现（Service 层，授权码的<em>消费</em>侧，服务端到服务端）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.controller.SsoExchangeController} 的唯一下游。
 * 调用方凭据已由 {@link com.airagent.iam.webapi.sso.SsoExchangeInterceptor} 完成核验与限流，
 * 本类只处理业务凭证与派生会话签发；不读 Cookie、不解析 {@code Authorization} 头、不直读表。
 *
 * <p>一次性与原子性：ticket 与 state 都以 SHA-256 摘要为主键，由 SECURITY DEFINER 函数以
 * <em>单条</em> {@code UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() RETURNING ...}
 * 完成"校验—置位—取回"，重放与并发天然失败（第二个事务命中 0 行）。兑换成功后原始值即作废，
 * 库内只留下摘要与 {@code consumed_at} 时刻。
 *
 * <p>失败时的凭证消耗差异（真实边界，勿按"要么全成要么全不变"理解）：
 * <ul>
 *   <li>ticket 不符（不存在/过期/已用/客户端或回调不匹配）→ 未消费任何行，401；</li>
 *   <li>ticket 命中但 state 不存在/过期/已用 → 方法返回 {@code null} 而<em>不</em>抛异常，
 *       事务照常提交，于是 <em>ticket 已被消费</em>：这一次兑换的凭证被整体烧掉，
 *       重放同一请求必然失败，401；</li>
 *   <li>state 命中但登记的 client_id 或 redirect_uri 与本请求不符 → 在事务内抛 400，
 *       回滚使两张凭证<em>都</em>回到未消费状态。</li>
 * </ul>
 *
 * <p>受众与派生会话：静态校验与凭证消费都通过后，才对 ticket 绑定的中央会话 id 重新执行
 * "Redis 存活 + PG 权威快照"双检（{@link SessionService#requireCurrentBySessionId}），
 * 再按注册客户端的 {@code audience} 签发受众受限的独立应用会话——该会话经
 * {@code central_session_id}（见 V16）挂到中央会话之下，中央的退出、切企业与续期由数据库
 * 触发器 {@code auth_sessions_synchronize_central} 原子传播到它。派生会话的时限被中央
 * 剩余时间夹住，{@code auth.sso_exchange} 审计也在签发事务内写入。
 *
 * @author Acerola
 */
@Service
public class SsoExchangeServiceImpl implements SsoExchangeService {

    /** 票据/state 原子领取数据访问 */
    private final SsoMapper ssoMapper;
    /** 编程式事务边界 */
    private final TransactionTemplate tx;
    /** 派生会话签发与双检 */
    private final SessionService sessionService;

    /**
     * 构造兑换服务。
     *
     * @param ssoMapper      SSO 数据访问，提供 ticket/state 的原子领取
     * @param tx             编程式事务边界，把两张凭证的消费包成一次提交或一次回滚
     * @param sessionService 权威会话服务，负责源会话复核与受众受限派生会话签发
     */
    public SsoExchangeServiceImpl(SsoMapper ssoMapper, TransactionTemplate tx,
                              SessionService sessionService) {
        this.ssoMapper = ssoMapper;
        this.tx = tx;
        this.sessionService = sessionService;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现顺序：请求体形状（必填、长度上界 ticket 256 / state 256 / redirect_uri 512）
     * → 回调与注册值<em>精确全串</em>比对（此时尚未消费任何凭证，故"回调不符"是可重试的 400）
     * → {@link #consumeGrant} 在单事务内原子领取两张凭证 → 源中央会话权威复核
     * → {@link SessionService#issueSsoSession} 按 {@code client.audience()} 签发派生会话。
     *
     * <p>复核为什么必须在消费之后再做一次：ticket 与 state 都签发于授权时刻，之后最长还要等
     * 一个回调往返才可兑换（state 有效期 {@code iam.sso.state-ttl-seconds} 缺省 600 秒、
     * ticket 有效期 {@code iam.sso.ticket-ttl-seconds} 缺省 30 秒）；这期间中央可能已退出、
     * 企业已停用或授权代次已推进。因此凭 ticket 取回的会话 id 仍要走与 Bearer 链路完全相同的
     * 权威双检，绝不以"ticket 有效"替代"会话有效"。
     *
     * <p>注意 state 的字符集校验只在授权侧施加（{@code \p{Graph}{1,256}}）；兑换侧对 ticket/state
     * 只判空白与长度上界，实际可用性由摘要主键命中与否决定，格式错误的值同样落在 401 分支。
     */
    @Override
    public LoginVO exchange(SsoClientView client, SsoExchangeDTO req) {
        if (req == null || blank(req.ticket()) || blank(req.redirectUri()) || blank(req.state())) {
            throw ApiException.badRequest("ticket、redirect_uri、state 必填");
        }
        if (req.ticket().length() > 256 || req.state().length() > 256
                || req.redirectUri().length() > 512) {
            throw ApiException.badRequest("SSO 参数超长");
        }
        if (!client.callbackUrl().equals(req.redirectUri())) {
            throw ApiException.badRequest("redirect_uri 与注册回调不一致");
        }

        UUID sourceSessionId = tx.execute(status -> consumeGrant(client, req));
        if (sourceSessionId == null) {
            throw ApiException.unauthenticated("ticket 或 state 无效、已过期或已被使用");
        }
        CurrentSession source = sessionService.requireCurrentBySessionId(sourceSessionId);
        return sessionService.issueSsoSession(source, client.audience());
    }

    /**
     * 事务内的凭证原子领取：先 ticket 后 state，并做绑定一致性判定。
     *
     * <p>ticket 领取条件是三条件合取（摘要主键 + client_id + redirect_uri），其中 client_id
     * 取自<em>已认证</em>的凭据结果而非请求体自述；它返回的中央会话 id 就是本方法的唯一产出。
     * state 领取条件只含摘要与有效性，因此登记的客户端与回调必须在拿到 {@link SsoStateDO} 后
     * 由本方法比对——不等即抛异常回滚整个事务，已置位的 ticket 一并撤销。
     * state 行上的 {@code handle_digest} 不参与判定（XML 未映射该列）：兑换代表的是
     * ticket 绑定的中央会话，而不是某个浏览器句柄。
     *
     * @param client 已认证的 SSO 客户端视图，提供 clientId 用于与两张凭证的登记值比对
     * @param req    已通过形状与回调校验的请求体
     * @return ticket 绑定的中央会话 id；返回 {@code null} 表示 ticket 或 state 未能领取
     *         （不存在、过期、已用），调用方据此给出不可区分的 401
     * @throws ApiException 400 state 虽被成功领取，但其登记的 clientId 或 redirectUri 与本请求不符
     *                      ——该异常在事务内抛出，两张凭证的置位都回滚
     */
    private UUID consumeGrant(SsoClientView client, SsoExchangeDTO req) {
        UUID sourceSessionId = ssoMapper.consumeTicket(OpaqueTokens.digest(req.ticket()),
                client.clientId(), req.redirectUri());
        if (sourceSessionId == null) {
            return null;
        }
        SsoStateDO state = ssoMapper.consumeState(OpaqueTokens.digest(req.state()));
        if (state == null) {
            return null;
        }
        if (!client.clientId().equals(state.clientId()) || !req.redirectUri().equals(state.redirectUri())) {
            throw ApiException.badRequest("state 与客户端或回调不匹配");
        }
        return sourceSessionId;
    }

    /**
     * 参数空判定：{@code null} 与全空白都视为未提供。
     *
     * @param value 待判定的文本
     * @return 未提供或仅由空白组成返回 {@code true}
     */
    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
