package com.airagent.iam.webapi.sso.entity;

import java.util.List;

/** 授权跳转所需的注册信息，不读取客户端密钥。 */
public record SsoRegistrationDO(String clientId, String callbackUrl, List<String> origins, String status) {
}
