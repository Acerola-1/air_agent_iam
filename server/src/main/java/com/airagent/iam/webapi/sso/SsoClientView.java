package com.airagent.iam.webapi.sso;

import java.util.List;

/** sso_clients 单行视图（经 SECURITY DEFINER 核验，调用方不直读表）。 */
public record SsoClientView(
        String clientId,
        String name,
        String callbackUrl,
        List<String> origins,
        String audience,
        String status
) {
}
