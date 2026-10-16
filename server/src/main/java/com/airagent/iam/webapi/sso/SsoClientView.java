package com.airagent.iam.webapi.sso;

import java.util.List;

/**
 * {@code iam.sso_clients} 单行的安全视图（record，跨 Mapper / 拦截器 / 服务层传递的已认证客户端事实）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.sso.mapper.SsoMapper#authenticate} 或
 * {@link com.airagent.iam.webapi.sso.mapper.SsoMapper#authenticateBearer} 返回，SQL 走
 * SECURITY DEFINER 函数 {@code iam_auth.authenticate_sso_client} / {@code iam_auth.authenticate_sso_bearer}
 * （见 V11、V17），调用方不直读表；由 {@link SsoExchangeInterceptor} 写入请求属性
 * {@link SsoExchangeInterceptor#SSO_CLIENT_ATTRIBUTE}，供兑换服务当作"已核验凭据"使用。
 *
 * <p>密钥边界：视图<em>不含</em> {@code secret_digest}——两个核验函数都只在服务端把传入的
 * SHA-256 摘要与列比对，命中才返回其余列，因此明文密钥与摘要都不经本对象外流。
 * 客户端密钥明文只来自配置 {@code iam.sso.clients.*.secret}，库内仅存摘要。
 *
 * <p>与授权侧视图 {@link com.airagent.iam.webapi.sso.entity.SsoRegistrationDO} 的区别：
 * 本视图多出 {@code name} 与 {@code audience}，是兑换链路"凭据即身份"的完整结果；
 * 后者用于尚未认证、只需回调与 Origin 白名单判定的授权链路。
 *
 * @param clientId    客户端标识；兑换时与 ticket/state 登记的 client_id 比对，也是限流 key 的主体
 * @param name        人类可读名称，仅用于展示与日志语境，不参与任何判定
 * @param callbackUrl 注册的<em>精确</em>回调地址；兑换请求体的 {@code redirect_uri} 必须与之全串相等
 * @param origins     浏览器 Origin 精确白名单；兑换端点（服务端到服务端）不使用该字段
 * @param audience    受众绑定，取值 {@code air-agent} / {@code knowledge} / {@code iam-admin}
 *                    （由列 CHECK 约束兜底）；兑换成功后写入派生会话的 {@code login_audience}
 * @param status      客户端状态，仅 {@code active} / {@code disabled}；核验函数只放行 {@code active}
 * @author Acerola
 */
public record SsoClientView(
        String clientId,
        String name,
        String callbackUrl,
        List<String> origins,
        String audience,
        String status
) {
}
