package com.airagent.iam.internal.service;

import com.airagent.iam.internal.dto.KnowledgeDelegationDTO;
import com.airagent.iam.internal.vo.KnowledgeDelegationVO;
import com.airagent.iam.security.internal.InternalClient;

/**
 * 知识只读用户委托签发（Service 接口层）。
 *
 * <p>只有登记了 {@code knowledge-delegation:issue} scope、且声明受众为 {@code knowledge}
 * 的内部客户端，才能用自己名下的 {@code langgraph-runtime} 执行引用申请一条单操作、
 * 最长 60 秒的只读委托。签发不扩大源身份权限，也不产生新的登录会话。
 */
public interface KnowledgeDelegationService {

    /** 委托目标受众，固定 {@code knowledge}。 */
    String AUDIENCE = "knowledge";

    /** 委托令牌前缀；仅用于 IAM 内部路由到委托内省分支，前缀本身不是秘密。 */
    String TOKEN_PREFIX = "kdl_";

    /**
     * 签发一条知识只读委托。
     *
     * @param client 已认证且持有签发 scope 的内部客户端
     * @param req    签发请求
     * @return 委托令牌（仅本次响应出现）与源身份快照
     * @throws com.airagent.iam.web.error.ApiException 400 协议不合法；403 无知识权限或客户端未注册受众；
     *         401 源引用/会话不可用；409 声明企业与源上下文不一致；503 依赖不可用
     */
    KnowledgeDelegationVO issue(InternalClient client, KnowledgeDelegationDTO req);
}
