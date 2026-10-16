package com.airagent.iam.security.internal;

import java.util.List;

/**
 * 已认证内部客户端（机器主体，realm {@code internal_client}）的请求作用域视图。
 *
 * <p>分层位置：安全层的只读值对象，由 {@link com.airagent.iam.security.internal.mapper.InternalClientMapper}
 * 从 {@code iam.internal_clients} 行经构造器映射得到，经 {@link InternalClientAuthenticator} 交给
 * {@link InternalClientInterceptor} 与内部端点服务消费；它不是 HTTP 响应模型，因此不带 Swagger 注解，
 * 也不含任何密钥材料（表里的 {@code secret_digest} 列刻意未被 SELECT）。
 *
 * <p>时效边界：每个请求都实时回 PostgreSQL 主库核验（{@code iam_auth.authenticate_internal_client}
 * 与 {@code iam_auth.authenticate_internal_bearer}），Mapper 两条语句均 {@code useCache="false"}，
 * 且全局关闭二级缓存、一级缓存为 STATEMENT——不存在凭据缓存或正向授权缓存，客户端被停用、
 * 撤销或轮换密钥后，下一次请求立刻反映新状态。
 *
 * <p>白名单语义：{@code scopes} 与 {@code audiences} 是两份独立白名单，分别由不同层裁决——
 * scope 由 {@link InternalClientInterceptor#authenticateAndAuthorize(String, String)} 按端点要求比对，
 * audience 由业务层比对（{@link com.airagent.iam.internal.service.IntrospectionService} 的注册受众、
 * {@link com.airagent.iam.internal.service.RuntimeTicketService} 的 {@code langgraph-runtime}）。
 * 数据库列 {@code text[]} 对元素取值无 CHECK 约束，取值口径来自预置路径
 * （{@code iam_auth.ensure_internal_client}）与运维写库；本项目实际使用的 scope 只有
 * {@code identity:introspect} 与 {@code runtime-ticket:issue}。
 *
 * @param clientId  客户端标识，对应 {@code iam.internal_clients.client_id}（全库唯一），
 *                  同时是限流计数键的主体部分与 {@code verification_ref} 的归属主体
 * @param name      展示名，仅用于人工识别；当前 Java 侧不参与任何判定
 * @param scopes    已授予的权限范围列表，映射自 {@code text[]}，元素形如 {@code identity:introspect}；
 *                  永不为 {@code null}（列为 NOT NULL，类型处理器亦把 NULL 归一化为空列表），
 *                  顺序与数据库数组一致、不做去重与排序
 * @param audiences 允许请求的受众白名单，元素形如 {@code langgraph-runtime}、{@code air-agent}；
 *                  同样永不为 {@code null}，空列表表示该客户端不得请求任何受众
 * @param status    行状态，取值为 {@code active} / {@code disabled} / {@code revoked}；
 *                  两个核验函数都只返回 {@code active} 行，因此本字段在实践中恒为 {@code active}，
 *                  仅作行形状映射保留，调用方不再据它做二次判定
 * @author Acerola
 */
public record InternalClient(
        String clientId,
        String name,
        List<String> scopes,
        List<String> audiences,
        String status
) {

    /**
     * 判断客户端是否被授予指定权限范围，供拦截器做 scope 裁决。
     *
     * @param scope 端点要求的 scope 码（区分大小写的精确匹配，不做前缀或通配）；
     *              {@code null} 视为不命中（列表元素本身不含 {@code null}）
     * @return 命中返回 {@code true}；{@code scopes} 为 {@code null} 或不含该值返回 {@code false}
     */
    public boolean hasScope(String scope) {
        return scopes != null && scopes.contains(scope);
    }

    /**
     * 判断客户端是否注册了指定受众，供内部端点服务做受众白名单裁决。
     *
     * @param audience 请求携带的受众（区分大小写的精确匹配）；{@code null} 视为不命中
     * @return 命中返回 {@code true}；{@code audiences} 为 {@code null} 或不含该值返回 {@code false}
     */
    public boolean hasAudience(String audience) {
        return audiences != null && audiences.contains(audience);
    }
}
