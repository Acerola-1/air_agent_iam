package com.airagent.iam.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Sa-Token 会话存储的 RedisTemplate 序列化配置（Config 层）。
 *
 * <p>键用 String 序列化（与 DigestStpLogic 的摘要键构形一致），值用 JDK 序列化
 * （与 sa-token-redis-template 的存取格式互操作）。Redis 仅作会话存活索引，
 * 权威状态在 PostgreSQL；实例为项目专用，不与其它应用共用。
 *
 * @author Acerola
 */
@Configuration
public class RedisConfig {

    /**
     * 构建会话读写用的 RedisTemplate。
     *
     * @param connectionFactory Boot 按 spring.data.redis.* 自动装配的连接工厂
     * @return 已完成属性初始化（afterPropertiesSet）的模板实例
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        StringRedisSerializer keySerializer = new StringRedisSerializer();
        JdkSerializationRedisSerializer valueSerializer = new JdkSerializationRedisSerializer();
        template.setKeySerializer(keySerializer);
        template.setHashKeySerializer(keySerializer);
        template.setValueSerializer(valueSerializer);
        template.setHashValueSerializer(valueSerializer);
        template.afterPropertiesSet();
        return template;
    }
}
