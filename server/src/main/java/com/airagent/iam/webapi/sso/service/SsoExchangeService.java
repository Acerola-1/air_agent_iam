package com.airagent.iam.webapi.sso.service;

import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;

/**
 * SSO 一次性票据兑换的业务接口（Service 层契约，实现见
 * {@link com.airagent.iam.webapi.sso.service.impl.SsoExchangeServiceImpl}）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.controller.SsoExchangeController} 唯一的下游。
 * 调用方凭据已由 {@link com.airagent.iam.webapi.sso.SsoExchangeInterceptor} 经
 * {@link com.airagent.iam.webapi.sso.SsoClientAuthenticator} 核验并限流，本接口拿到的是
 * <em>已认证</em>的 {@link SsoClientView}，不再自行解析 {@code Authorization} 头。
 *
 * <p>职责边界：请求体形状校验、回调精确匹配、ticket 与 state 的原子消费与绑定一致性、
 * 源中央会话的权威复核，以及受众受限派生会话的签发（委派
 * {@link com.airagent.iam.auth.service.SessionService#issueSsoSession}）。
 * 兑换是服务端到服务端动作：结果令牌只出现在本次响应体，浏览器与 URL 都看不到。
 *
 * @author Acerola
 */
public interface SsoExchangeService {

    /**
     * 消费一次性的 ticket 与 state，为同一人类签发受众绑定的独立应用会话。
     *
     * <p>顺序即安全边界：先做请求体与回调的静态校验，再在<em>单个</em>事务内原子领取两张凭证，
     * 事务提交后才对 ticket 指向的中央会话重新执行"Redis 存活 + PG 权威快照"双检，
     * 最后按注册受众 mint 派生会话。任一步失败都不会留下可用的凭证。
     *
     * <p>失败语义（对调用方刻意不可区分）：ticket 无效/过期/已用、state 无效/过期/已用，
     * 都返回同一句 401；state 虽有效但登记的客户端或回调与本请求不符则 400 并整体回滚，
     * 两张凭证都不被消费。
     *
     * @param client 已完成凭据核验的 SSO 客户端视图；提供 clientId、精确回调与受众绑定，
     *               由拦截器注入，正常链路非空（本方法不做空值兜底）
     * @param req    兑换请求体；{@code null}、三字段任一空白或超长都按 400 拒绝
     * @return 派生应用会话的 {@link LoginVO}，其中 {@code accessToken} 为一次性下发的原始令牌，
     *         只存在于这次服务端到服务端的响应
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失/字段空白/超长、
     *                                                回调与注册值不精确匹配、state 与客户端或回调不匹配；
     *                                                401 ticket 或 state 无效、已过期或已被使用，
     *                                                或源中央会话已撤销/过期/代次变旧；
     *                                                403 源会话所属企业或成员关系已停用、
     *                                                源会话非 workforce 人类会话；
     *                                                409 注册受众不合法（数据库 CHECK 23514）；
     *                                                503 Redis/PG 依赖故障
     * @throws IllegalStateException 派生会话的审计写入失败（Redis 会话已被补偿删除）
     */
    LoginVO exchange(SsoClientView client, SsoExchangeDTO req);
}
