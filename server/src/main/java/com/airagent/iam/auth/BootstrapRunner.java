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
 * 首启幂等引导组件（启动期基础设施，不属任何 HTTP 分层）：预置 SSO 客户端、
 * 超级管理员与内部 runtime 客户端。
 *
 * <p>以 {@link ApplicationRunner} 在容器刷新完成、开始对外服务之前执行一次，
 * {@code @Order(100)} 决定其与其它 ApplicationRunner 的相对次序。
 * 全部写入经 {@link InfrastructureMapper} 调用 {@code iam_auth.*} 的 SECURITY DEFINER 函数，
 * 因此不需要请求上下文，也不受 RLS 影响。
 *
 * <p>幂等语义（判定在数据库内完成，不是"整库为空"判定）：
 * <ul>
 *   <li>超级管理员按 {@code realm = workforce AND account = ?} 是否存在判定，已存在则不重置口令、
 *       不改动既有角色与授权；账号/口令未配置则整段跳过。</li>
 *   <li>SSO 客户端冲突时只同步名称/回调/Origin/受众，保留既有密钥摘要。</li>
 *   <li>内部 runtime 客户端冲突时会用本次摘要覆盖密钥并把修订 +1，即每次带凭据的启动都是一次轮换。</li>
 * </ul>
 *
 * <p>强度门禁：bootstrap 口令短于 12 字符、内部客户端或 SSO 客户端密钥短于 32 字符时直接抛
 * {@link IllegalStateException} 终止启动——拒绝以弱凭据对外服务，而不是降级运行。
 * 所有配置值只用于生成摘要，日志与审计中不出现口令或密钥原文。
 *
 * @author Acerola
 */
@Component
@Order(100)
public class BootstrapRunner implements ApplicationRunner {

    /** 引导过程日志，仅输出 account/client_id 与是否新建，不含任何秘密。 */
    private static final Logger LOGGER = LoggerFactory.getLogger(BootstrapRunner.class);

    /**
     * 平台超级管理员角色的固定 UUID，与种子迁移脚本登记的内置角色 id 一致。
     * 用固定 id 而非按 code 查询，使引导路径不依赖 RLS 与目录数据的可见性。
     */
    private static final UUID PLATFORM_SUPER_ADMIN_ROLE =
            UUID.fromString("01930000-0000-4000-8000-000000000301");

    /** 引导与预置的 SQL 网关（全部为 iam_auth 的 SECURITY DEFINER 函数）。 */
    private final InfrastructureMapper infrastructureMapper;

    /** BCrypt 摘要生成器；bootstrap 口令在此转换后立即丢弃明文。 */
    private final PasswordHasher passwordHasher;

    /** {@code iam.*} 配置来源：bootstrap 账号、内部客户端与 SSO 客户端清单。 */
    private final IamProperties props;

    /**
     * 构造引导组件。
     *
     * @param infrastructureMapper 引导与客户端预置的数据访问
     * @param passwordHasher       口令摘要生成器
     * @param props                {@code iam.*} 配置
     */
    public BootstrapRunner(InfrastructureMapper infrastructureMapper, PasswordHasher passwordHasher, IamProperties props) {
        this.infrastructureMapper = infrastructureMapper;
        this.passwordHasher = passwordHasher;
        this.props = props;
    }

    /**
     * 执行启动引导。
     *
     * <p>顺序固定：先预置 SSO 客户端（与 bootstrap 账号是否配置无关，纯 SSO 部署同样需要），
     * 再判断 bootstrap 账号/口令——任一为空即记录日志后返回（此时内部客户端也不会预置），
     * 否则校验口令强度、生成摘要并幂等确保账号存在，最后预置内部 runtime 客户端。
     *
     * @param args 启动参数，本组件不读取
     * @throws IllegalStateException bootstrap 口令少于 12 字符，或客户端密钥少于 32 字符，
     *                               拒绝以弱凭据启动（启动失败关闭）
     */
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

    /**
     * 幂等预置本机合成 runtime 内部客户端。
     *
     * <p>配置项缺失或 id/secret 任一为空则跳过；密钥少于 32 字符直接终止启动。
     * 只有 SHA-256 摘要进入数据库，scope 与 audience 由 Mapper 固定为
     * {@code identity:introspect}、{@code runtime-ticket:issue} 与 {@code langgraph-runtime}，
     * 不接受配置扩展。已存在时该调用会轮换密钥并递增修订号。
     */
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

    /**
     * 幂等预置配置登记的合成 SSO 客户端（本机验收用的两个自有 BFF）。
     *
     * <p>遍历 {@code iam.sso.clients}，对每个客户端：id 或 secret 为空则单独跳过并记录日志；
     * 密钥少于 32 字符终止启动；名称缺省为"合成 SSO 客户端 &lt;key&gt;"；origins 缺省为空列表，
     * 与回调地址一起按精确匹配登记（不做前缀或通配）。已存在的客户端不会被覆盖密钥，
     * 只同步名称/回调/Origin/受众。
     *
     * <p>受众合法性由数据库 CHECK 兜底：非 {@code air-agent} / {@code knowledge} /
     * {@code iam-admin} 取值以 SQLSTATE 23514 报错并使启动失败。
     */
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

    /**
     * 配置值空判定：{@code null} 或全空白都视为"未配置"。
     *
     * @param value 待判定的配置文本
     * @return 未配置或空白返回 {@code true}
     */
    private boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
