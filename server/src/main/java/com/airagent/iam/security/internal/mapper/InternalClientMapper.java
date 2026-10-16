package com.airagent.iam.security.internal.mapper;

import com.airagent.iam.security.internal.InternalClient;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 内部客户端核验的数据访问（Mapper 层，SQL 见
 * {@code mapper/security/internal/InternalClientMapper.xml}）。
 *
 * <p>运行在 iam_app 请求角色下：{@code iam.internal_clients} 只启用了 RLS 而未创建任何策略
 * （非 FORCE），因此该角色直接查询看不到任何行，唯一读取途径是两个 {@code SECURITY DEFINER}
 * 函数 {@code iam_auth.authenticate_internal_client} 与 {@code iam_auth.authenticate_internal_bearer}。
 * 两条语句都以 {@code SELECT ... FROM 函数(...)} 的行集形式取列
 * {@code client_id, name, scopes, audiences, status}，不读 {@code secret_digest}；
 * {@code scopes}/{@code audiences} 为 {@code text[]}，经全局
 * {@link com.airagent.iam.common.typehandler.TextArrayTypeHandler} 映射为不可变
 * {@code List<String>}（NULL 归一化为空列表）。
 *
 * <p>缓存与实时性：两条语句均 {@code useCache="false"}，叠加全局关闭二级缓存、
 * 一级缓存 STATEMENT、执行器 SIMPLE，因此每次调用都是一次主库往返，客户端状态变化即时可见。
 *
 * @author Acerola
 */
@Mapper
public interface InternalClientMapper {

    /**
     * HTTP Basic 形态的核验：按客户端 id 定位行，再比对密钥摘要。
     *
     * <p>函数把"不存在""摘要不符""状态非 {@code active}"三种情形折叠为同一个
     * RAISE（SQLSTATE 28000），以阻止调用方枚举客户端 id；因此本方法正常返回时
     * {@code status} 恒为 {@code active}。
     *
     * @param clientId 客户端标识（{@code iam.internal_clients.client_id}，全库唯一）；
     *                 未登记的值与错误凭据不可区分
     * @param digest   客户端密钥的 SHA-256 十六进制小写摘要（64 字符），由
     *                 {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)} 生成；
     *                 密钥原文不下达到本层
     * @return 已认证的客户端行；SQL 以函数异常表达失败，返回 {@code null} 仅出现在
     *         函数返回零行的防御性场景，调用方按未认证处理
     * @throws org.springframework.dao.DataAccessException 凭据无效或客户端已停用（SQLSTATE 28000）、
     *                                                     以及连接/超时类故障；由
     *                                                     {@link com.airagent.iam.security.internal.InternalClientAuthenticator}
     *                                                     翻译为 401/503
     */
    InternalClient authenticate(@Param("clientId") String clientId, @Param("digest") String digest);

    /**
     * Bearer 形态的核验：只按密钥摘要在内部客户端登记表内查找，不看客户端 id。
     *
     * <p>函数为纯 SQL（不 RAISE），命中条件是三件事同时成立：摘要相等、状态为 {@code active}、
     * 且全表持有该摘要的行恰好为 1（同摘要被两个客户端共享时两条都判无效，避免归属歧义）。
     * 该表只登记机器主体，人类会话令牌与服务账号令牌在此一律查不到，两套凭据空间因此天然隔离。
     *
     * @param digest 凭据原文的 SHA-256 十六进制小写摘要（64 字符）
     * @return 已认证的客户端行；未命中、状态非活跃或摘要不唯一时返回 {@code null}
     * @throws org.springframework.dao.DataAccessException 连接/超时等数据库故障（本函数不以
     *                                                     SQLSTATE 表达认证失败）
     */
    InternalClient authenticateBearer(@Param("digest") String digest);
}
