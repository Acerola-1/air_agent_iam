package com.airagent.iam.config;

import cn.dev33.satoken.stp.StpUtil;
import com.airagent.iam.security.satoken.DigestStpLogic;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;

/**
 * 在容器开始接收请求前替换全局 StpLogic 为摘要键实现。
 */
@Configuration
public class SaTokenConfiguration {

    @PostConstruct
    void installDigestLogic() {
        StpUtil.setStpLogic(new DigestStpLogic());
    }
}
