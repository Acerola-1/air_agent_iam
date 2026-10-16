package com.airagent.iam;

import com.airagent.iam.config.IamProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * IAM 独立服务启动入口。
 *
 * <p>装配要点：组件扫描本包全部层（Controller/Service/Mapper/拦截器/配置）；
 * 启用 {@link IamProperties}（{@code iam.*} 配置绑定）与 Spring 定时调度
 * （OutboxRelay 等后台任务依赖）。HTTP 仅监听回环地址（server.address 固定
 * 127.0.0.1），Flyway 在启动期完成迁移。
 *
 * @author Acerola
 */
@SpringBootApplication
@EnableConfigurationProperties(IamProperties.class)
@EnableScheduling
public class IamApplication {

    /**
     * 进程入口：启动 Spring 容器并阻塞至应用停止。
     *
     * @param args 命令行参数，透传给 Spring Boot（可用于覆盖配置属性）
     */
    public static void main(String[] args) {
        SpringApplication.run(IamApplication.class, args);
    }
}
