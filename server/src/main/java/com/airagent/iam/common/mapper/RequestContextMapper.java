package com.airagent.iam.common.mapper;

import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 设置当前 Spring 事务中的可信数据库请求上下文（Mapper 层）。
 *
 * <p>经 SECURITY DEFINER 函数 {@code iam_auth.set_request_context} 以事务级
 * {@code set_config} 写入 {@code app.user_id / app.tenant_id / app.is_platform}，
 * 事务结束即失效；RLS 策略与触发器以此为事实来源。
 *
 * @author Acerola
 */
@Mapper
public interface RequestContextMapper {

    /**
     * 在调用方事务内设置本地上下文。上下文只声明"我是谁、在哪个企业"，
     * 权限裁决仍须服务层显式校验，禁止把本方法当作授权来源。
     *
     * @param userId   已认证用户标识；{@code null} 时对应 GUC 置空文本
     * @param tenantId 已认证当前企业标识；平台线传 {@code null}
     * @param platform 是否为已授权的平台操作（{@code app.is_platform=on}）
     * @return 数据库函数执行结果行数（恒为 1，异常即抛）
     */
    int setContext(@Param("userId") UUID userId,
                   @Param("tenantId") UUID tenantId,
                   @Param("platform") boolean platform);
}
