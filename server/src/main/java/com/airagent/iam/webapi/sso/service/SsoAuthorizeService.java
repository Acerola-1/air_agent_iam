package com.airagent.iam.webapi.sso.service;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.webapi.BrowserHandleRow;

/**
 * 中央 SSO 授权跳转的业务接口（Service 层契约，实现见
 * {@link com.airagent.iam.webapi.sso.service.impl.SsoAuthorizeServiceImpl}）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.controller.SsoController} 唯一的下游。
 * 调用方必须已经完成"浏览器中央会话"核验——该接口不接受原始令牌，只接受拦截器
 * 已核验的 {@link CurrentSession} 与会话句柄行，因此授权入口天然要求登录态：
 * 中央不在这里做登录，登录页由前端引导完成后才发起跳转。
 *
 * <p>职责边界：注册客户端存在性与状态、回调地址<em>精确</em>匹配、Origin 白名单、
 * 本机回环限制、限流、一次性 state/ticket 的登记与审计，全部在本服务裁决；
 * Controller 只做参数透传与 303 装配。
 *
 * @author Acerola
 */
public interface SsoAuthorizeService {

    /**
     * 校验一次授权请求并登记配对的 state/ticket，返回消费方回调的绝对跳转地址。
     *
     * <p>返回的 URL 只在<em>全部</em>校验通过后产生：回调地址后拼接一次性 {@code ticket} 与
     * 原样回传的 {@code state}（两者均 URL 编码），人类令牌既不进入该 URL、也不出现在任何
     * 响应体或日志里。失败一律以 {@link com.airagent.iam.web.error.ApiException} 抛出，
     * 由 {@link com.airagent.iam.web.error.GlobalExceptionHandler} 转为统一错误信封，
     * <em>不</em>重定向回调用方（错误码枚举在消费方 BFF 侧，见交接疑点）。
     *
     * @param current     已双重核验的浏览器中央会话快照；提供 userId、当前企业与会话 id，
     *                    ticket 正是绑定到它的 {@code sessionId}。正常链路由拦截器注入，非空
     * @param handle      当前浏览器会话句柄行；只取 {@code digest} 与 state 一起登记。
     *                    正常链路非空，本方法不校验其为空
     * @param clientId    目标 SSO 客户端标识；必填非空白、长度上界 128
     * @param redirectUri 期望回调地址；必填非空白、长度上界 512，必须与注册 {@code callback_url}
     *                    逐字相等且为本机回环 http，否则 400
     * @param state       消费方生成的一次性一致性值；必填非空白，仅限可打印非空白字符
     *                    （正则 {@code \p{Graph}{1,256}}），长度上界 256
     * @param origin      请求的 {@code Origin} 头原值；{@code null} 或空白视为跳过 Origin 校验
     *                    （浏览器直接导航可能不带该头），非空则必须命中该客户端登记的精确白名单
     * @return 拼接完成的 303 跳转目标绝对地址（{@code redirectUri} + {@code ticket} + {@code state}），
     *         由 Controller 写入 {@code Location} 头
     * @throws com.airagent.iam.web.error.ApiException 400 必填缺失/超长/state 字符不合法、
     *                                                客户端不存在或已停用、回调不精确匹配、
     *                                                回调非本机回环 http 或地址不可解析；
     *                                                403 Origin 未注册到该客户端；
     *                                                429 该会话的授权发起频率超限；
     *                                                503 限流或数据库依赖故障
     * @throws IllegalStateException 同事务内的审计写入失败，state/ticket 登记整体回滚
     */
    String authorize(
            CurrentSession current,
            BrowserHandleRow handle,
            String clientId,
            String redirectUri,
            String state,
            String origin);
}
