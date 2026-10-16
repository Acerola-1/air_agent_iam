package com.airagent.iam.config;

import cn.dev33.satoken.stp.StpUtil;
import com.airagent.iam.security.satoken.DigestStpLogic;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;

/**
 * Sa-Token 全局逻辑装配（Config 层）。
 *
 * <p>在容器开始接收请求前把默认 StpLogic 替换为 {@link DigestStpLogic}：
 * 令牌只以 SHA-256 摘要形态进入 Redis 键，原文不落存储。替换发生在
 * {@code @PostConstruct}，早于任何登录/校验调用，因此不存在混用两种键构形的窗口。
 *
 * @author Acerola
 */
@Configuration
public class SaTokenConfiguration {

    /**
     * 将 Sa-Token 静态入口 StpUtil 的全局逻辑指向摘要实现。
     *
     * <p>DigestStpLogic 无注入依赖，按 Sa-Token 惯例以裸实例全局替换。
     */
    @PostConstruct
    void installDigestLogic() {
        StpUtil.setStpLogic(new DigestStpLogic());
    }
}
