package com.airagent.iam.ops;

import java.util.Map;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * 一次性运维命令入口。
 *
 * <p>以非 Web 上下文启动，执行完立即关闭；不监听端口、不注册 HTTP 端点、不运行启动引导。
 * 必须在 {@code server/} 目录显式调用：
 * <pre>
 * ./mvnw -q -DskipTests spring-boot:run \
 *   -Dspring-boot.run.main-class=com.airagent.iam.ops.OpsApplication \
 *   -Dspring-boot.run.arguments="--iam.ops.command=plan --iam.ops.root-user-id=..."
 * </pre>
 *
 * @author Acerola
 */
public final class OpsApplication {

    private OpsApplication() {
    }

    /**
     * 启动独立运维上下文并执行命令。
     *
     * @param args Spring 参数；命令参数以 {@code --iam.ops.*} 传入
     */
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(OpsConfiguration.class);
        app.setWebApplicationType(WebApplicationType.NONE);
        app.setBannerMode(Banner.Mode.OFF);
        app.setDefaultProperties(Map.of("iam.ops.enabled", "true"));
        int exitCode = 1;
        try (ConfigurableApplicationContext context = app.run(args)) {
            exitCode = context.getBean(OpsRunner.class).run();
        } catch (RuntimeException e) {
            System.err.println("IAM 运维命令失败: " + e.getMessage());
        }
        System.exit(exitCode);
    }
}
