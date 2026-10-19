package com.airagent.iam.ops;

import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.ops.mapper.OpsMapper;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * 运维命令的独立 Spring 上下文。
 *
 * <p>只有显式以 {@link OpsApplication} 启动并设置 {@code iam.ops.enabled=true} 时才装配；
 * 正常 Web 服务启动不会加载本配置，也不会把一次性授权/清理命令挂到生命周期或 HTTP 路由上。
 * 复用 DataSource、Flyway、MyBatis 与通用审计/上下文 Mapper，但不加载 Web、会话与引导组件。
 *
 * @author Acerola
 */
@Configuration
@ConditionalOnProperty(name = "iam.ops.enabled", havingValue = "true")
@EnableAutoConfiguration
@EnableConfigurationProperties(OpsProperties.class)
@MapperScan({"com.airagent.iam.ops.mapper", "com.airagent.iam.common.mapper"})
public class OpsConfiguration {

    /** 一次性运维编排服务；仅在显式运维上下文中注册。 */
    @Bean
    public OpsService opsService(OpsMapper mapper, RequestContextMapper contextMapper,
                                 AdminEventMapper eventMapper, TransactionTemplate tx,
                                 ObjectMapper json, OpsProperties props) {
        return new OpsService(mapper, contextMapper, eventMapper, tx, json, props);
    }

    /** 命令分发器；仅在显式运维上下文中注册。 */
    @Bean
    public OpsRunner opsRunner(OpsProperties props, OpsService service, ObjectMapper json) {
        return new OpsRunner(props, service, json);
    }
}
