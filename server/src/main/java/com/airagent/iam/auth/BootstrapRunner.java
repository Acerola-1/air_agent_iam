package com.airagent.iam.auth;

import com.airagent.iam.auth.entity.BootstrapUserDO;
import com.airagent.iam.auth.entity.ProvisionResultDO;
import com.airagent.iam.auth.mapper.InfrastructureMapper;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.password.PasswordHasher;
import com.airagent.iam.security.token.OpaqueTokens;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * 首启幂等引导超级管理员。账号/口令未配置则跳过；已存在不重置口令。
 */
@Component
@Order(100)
public class BootstrapRunner implements ApplicationRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(BootstrapRunner.class);
    private static final UUID PLATFORM_SUPER_ADMIN_ROLE =
            UUID.fromString("01930000-0000-4000-8000-000000000301");

    private final InfrastructureMapper infrastructureMapper;
    private final PasswordHasher passwordHasher;
    private final IamProperties props;

    public BootstrapRunner(InfrastructureMapper infrastructureMapper, PasswordHasher passwordHasher, IamProperties props) {
        this.infrastructureMapper = infrastructureMapper;
        this.passwordHasher = passwordHasher;
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) {
        ensureSsoClients();
        IamProperties.Bootstrap bootstrap = props.bootstrap();
        if (bootstrap == null
                || blank(bootstrap.account())
                || blank(bootstrap.password())) {
            LOGGER.info("未配置 bootstrap 账号/口令，跳过引导");
            return;
        }
        if (bootstrap.password().length() < 12) {
            throw new IllegalStateException("IAM_BOOTSTRAP_PASSWORD 长度至少 12，拒绝以弱口令启动");
        }
        String displayName = blank(bootstrap.displayName())
                ? "初始超级管理员"
                : bootstrap.displayName();
        String hash = passwordHasher.hash(bootstrap.password());

        BootstrapUserDO result = infrastructureMapper.ensureUser(bootstrap.account(), displayName,
                hash, PLATFORM_SUPER_ADMIN_ROLE);
        boolean created = result != null && result.wasCreated();
        LOGGER.info("Bootstrap 账号处理完成 account={} created={}", bootstrap.account(), created);
        ensureRuntimeClient();
    }

    /** 幂等预置本机合成 runtime 内部客户端；只存摘要，日志不出现秘密。 */
    private void ensureRuntimeClient() {
        IamProperties.ClientProvision client = props.internal() == null
                ? null : props.internal().runtimeClient();
        if (client == null || blank(client.id()) || blank(client.secret())) {
            LOGGER.info("未配置内部 runtime 客户端凭据，跳过预置");
            return;
        }
        if (client.secret().length() < 32) {
            throw new IllegalStateException(
                    "IAM_INTERNAL_RUNTIME_CLIENT_SECRET 长度至少 32，拒绝以弱密钥启动");
        }
        ProvisionResultDO result = infrastructureMapper.ensureRuntimeClient(client.id(), OpaqueTokens.digest(client.secret()));
        LOGGER.info("内部 runtime 客户端处理完成 client_id={} created={} revision={}",
                client.id(), result.wasCreated(), result.revision());
    }

    /** 幂等预置本机合成 SSO 客户端；只存摘要，回调与 Origin 精确登记，日志不出现秘密。 */
    private void ensureSsoClients() {
        IamProperties.Sso sso = props.sso();
        if (sso == null || sso.clients() == null || sso.clients().isEmpty()) {
            LOGGER.info("未配置 SSO 客户端，跳过预置");
            return;
        }
        sso.clients().forEach((key, client) -> {
            if (client == null || blank(client.id()) || blank(client.secret())) {
                LOGGER.info("SSO 客户端 {} 未配置 id/secret，跳过预置", key);
                return;
            }
            if (client.secret().length() < 32) {
                throw new IllegalStateException(
                        "SSO 客户端 " + key + " 密钥长度至少 32，拒绝以弱密钥启动");
            }
            String name = blank(client.name()) ? "合成 SSO 客户端 " + key : client.name();
            List<String> origins = client.origins() == null ? List.of() : client.origins();
            boolean created = infrastructureMapper.ensureSsoClient(client.id(), name,
                    OpaqueTokens.digest(client.secret()), client.callbackUrl(), origins, client.audience());
            LOGGER.info("SSO 客户端处理完成 client_id={} created={}", client.id(), created);
        });
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
