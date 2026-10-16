package com.airagent.iam.webapi.sso.entity;

import java.util.List;

/**
 * 授权跳转所需的 SSO 客户端注册信息（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.mapper.SsoMapper#selectClient} 的返回值，
 * SQL 为 {@code SELECT client_id, callback_url, origins, status FROM iam_auth.sso_client_get(#{clientId})}
 * （见 {@code resources/mapper/webapi/sso/SsoMapper.xml}）。表 {@code iam.sso_clients} 开启 RLS
 * 且无策略，请求角色 {@code iam_app} 无直读权限，只能经该 SECURITY DEFINER 函数单行键控访问。
 *
 * <p>密钥边界：{@code iam_auth.sso_client_get} 本身还返回 {@code secret_digest} 列，但 XML 刻意
 * 只取这四列，因此本 record <em>不含</em>任何密钥材料——授权入口这条链路在结构上就无法拿到
 * 客户端凭据。真实边界是：客户端密钥明文只来自配置 {@code iam.sso.clients.*.secret}（环境变量注入），
 * 启动预置时经 {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 转 SHA-256
 * 十六进制摘要写入 {@code iam.sso_clients.secret_digest}，明文<em>永不落库</em>、不进日志与审计；
 * 兑换链路的核验同样只比对摘要（见 {@link com.airagent.iam.webapi.sso.SsoClientAuthenticator}）。
 * 授权侧只需"回调地址 + Origin 白名单 + 状态"即可完成判定。
 *
 * @param clientId   客户端标识（{@code iam.sso_clients.client_id} 主键），由配置提供、非用户秘密
 * @param callbackUrl 注册的<em>精确</em>回调地址；授权与兑换两侧都以 {@code String.equals}
 *                   全串比对，不做前缀、子域或通配匹配
 * @param origins    该客户端登记的浏览器 Origin 精确白名单（列 {@code origins text[]}，
 *                   预置缺省为空列表）；只用于 {@code contains} 精确判定
 * @param status     客户端状态，仅 {@code active} / {@code disabled}；非 {@code active}
 *                   在授权入口即被拒绝
 * @author Acerola
 */
public record SsoRegistrationDO(String clientId, String callbackUrl, List<String> origins, String status) {
}
