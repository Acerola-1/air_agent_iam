package com.airagent.iam.webapi.sso.controller;

import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.SsoExchangeInterceptor;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;
import com.airagent.iam.webapi.sso.service.SsoExchangeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SSO 应用令牌兑换 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>认证面：<em>SSO 客户端凭据</em>（文档方案 {@code internalClient}），由
 * {@link SsoExchangeInterceptor} 在进入本方法前完成——{@code Authorization: Bearer <客户端密钥>}，
 * 兼容 {@code Basic base64(client_id:client_secret)}，两者都只按 SHA-256 摘要与
 * {@code iam.sso_clients} 比对（见 {@link com.airagent.iam.webapi.sso.SsoClientAuthenticator}）。
 * 认证只针对"发起兑换的应用"，浏览器里的人类由请求体的一次性 {@code ticket} 代表；
 * 本路径不经 {@code BrowserSessionInterceptor}，也不受 {@code CsrfOriginInterceptor}
 * 的 {@code Authorization} 头拒绝约束（后者只覆盖 {@code /web-api/**} 与 {@code /v1/sso/authorize}）。
 *
 * <p>场景：消费方 BFF 收到中央 303 回调后，在<em>自己的服务端</em>用凭据兑换应用令牌。
 * 因此 {@code accessToken} 只出现在这一次服务端到服务端的响应里，浏览器与 URL 均不可见；
 * 兑换成功的派生会话经 {@code central_session_id} 挂在中央会话之下，
 * 中央退出/切企业/续期由数据库触发器原子传播。
 *
 * <p>本层只做属性提取与参数透传；形状校验、回调精确匹配、ticket/state 原子消费、
 * 源会话权威复核与受众绑定签发全部在 {@link SsoExchangeService} 裁决，
 * 错误统一由 {@code GlobalExceptionHandler} 转为错误信封。
 *
 * @author Acerola
 */
@Tag(name = "SSO 令牌兑换", description = "消费方服务端用客户端凭据兑换一次性 ticket，换取受众绑定的独立应用会话；"
        + "ticket 与 state 均消费即失效，重放一律 401")
@RestController
public class SsoExchangeController {

    /** SSO 兑换编排服务 */
    private final SsoExchangeService exchangeService;

    /**
     * 构造兑换入口。
     *
     * @param exchangeService 兑换业务服务，凭证消费与派生会话签发在其中完成
     */
    public SsoExchangeController(SsoExchangeService exchangeService) {
        this.exchangeService = exchangeService;
    }

    /**
     * 兑换一次性 ticket 为受众绑定的应用会话。
     *
     * <p>请求属性来源：{@link SsoClientView} 由 {@link SsoExchangeInterceptor} 在凭据核验与
     * 限流通过后写入 {@link SsoExchangeInterceptor#SSO_CLIENT_ATTRIBUTE}，因此到得了本方法就说明
     * 凭据已认证；本层不重复校验，也不接受请求体自述的客户端身份。
     *
     * <p>一次性语义：ticket 与 state 都以摘要主键经单条 {@code UPDATE ... RETURNING} 原子领取，
     * 消费即失效；并发或二次提交的第二个事务命中 0 行，与"过期""不存在"共用同一 401 消息。
     * 回调地址要与注册值精确相等（非前缀）才可能领取成功。
     *
     * <p>响应与缓存：成功返回 200 与 {@link LoginVO}（含一次性原始令牌），
     * 拦截器已对本路径写入 {@code Cache-Control: no-store}；本类覆写请求体
     * {@code toString()} 脱敏，令牌、ticket 与 state 都不进日志。
     *
     * @param request 当前 HTTP 请求；只用于取回拦截器注入的已认证客户端视图
     * @param body    兑换请求体，线格式字段为 {@code ticket}、{@code redirect_uri}、{@code state}
     *                （全局 SNAKE_CASE）；请求体缺失或任一字段空白由服务层按 400 拒绝
     * @return 派生应用会话的登录结果，{@code accessToken} 仅在本次响应中出现一次
     */
    @Operation(summary = "兑换一次性 ticket 为应用会话",
            description = "SSO 客户端凭据鉴权（Bearer 客户端密钥，兼容 Basic client_id:client_secret），"
                    + "由 SsoExchangeInterceptor 核验并按 clientId 限流。请求体三字段均必填；"
                    + "redirect_uri 必须与注册回调精确相等。ticket 与 state 各自原子消费、消费即失效，"
                    + "重放或过期统一 401；兑换成功后对 ticket 绑定的中央会话重新执行 Redis 存活 + PG 权威双检，"
                    + "再按注册受众签发派生会话。响应只回给调用方服务端，令牌不进浏览器与 URL",
            security = {@SecurityRequirement(name = "internalClient")})
    @ApiResponse(responseCode = "200", description = "兑换成功，返回受众绑定的应用会话登录结果（含一次性访问令牌）")
    @ApiResponse(responseCode = "400", description = "请求体缺失或 JSON 不合法、字段空白或超长、redirect_uri 与注册回调不一致、state 与客户端或回调不匹配")
    @ApiResponse(responseCode = "401", description = "客户端凭据无效或已停用；或 ticket/state 不存在、已过期、已被使用；或源中央会话已撤销/过期/代次变旧")
    @ApiResponse(responseCode = "403", description = "源会话所属企业或成员关系已停用，或源会话非 workforce 人类会话")
    @ApiResponse(responseCode = "409", description = "注册客户端的受众不合法（数据库 CHECK 违例）")
    @ApiResponse(responseCode = "429", description = "该客户端在窗口内的兑换次数超过 iam.rate-limit.internal-limit 配额")
    @ApiResponse(responseCode = "503", description = "Redis 限流/会话依赖或 PostgreSQL 依赖故障（失败关闭）")
    @PostMapping("/v1/internal/sso/exchange")
    public LoginVO exchange(HttpServletRequest request,
                                @RequestBody(required = false) SsoExchangeDTO body) {
        SsoClientView client = (SsoClientView) request
                .getAttribute(SsoExchangeInterceptor.SSO_CLIENT_ATTRIBUTE);
        return exchangeService.exchange(client, body);
    }
}
