package com.airagent.iam.internal.vo;

import com.airagent.iam.auth.vo.IdentityVO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 知识委托内省响应（{@code iam.knowledge-delegation-introspection.v1}）。
 *
 * <p>{@code identity} 使用与 {@code iam.identity.v1} 相同的人类投影结构，但权限只保留
 * 实时有效的 {@code knowledge:lib:*:read} 码；{@code delegation} 标记签发客户端与来源，
 * 使消费方能把委托身份与普通登录态明确区分。
 *
 * @param schemaVersion 固定 iam.knowledge-delegation-introspection.v1
 * @param active        委托与源身份是否仍可用
 * @param issuer        IAM 签发方
 * @param audience      固定 knowledge
 * @param operation     本次被核验的单一操作
 * @param identity      人类身份投影（权限已收窄到知识库读）
 * @param delegation    委托来源标记
 * @param evaluatedAt   服务端评估时刻
 */
@Schema(name = "KnowledgeDelegationIntrospectionVO",
        description = "知识委托内省：实时复核源会话/企业/成员/修订与知识权限")
public record KnowledgeDelegationIntrospectionVO(
        String schemaVersion,
        boolean active,
        String issuer,
        String audience,
        String operation,
        IdentityVO identity,
        Delegation delegation,
        String evaluatedAt
) {
    /**
     * 委托来源标记。
     *
     * @param issuingClientId 申请委托的 Agent 客户端
     * @param sourceAudience  源受众（langgraph-runtime）
     * @param sourceSessionId 源会话
     * @param operation       委托操作
     * @param expiresAt       委托失效时刻
     */
    public record Delegation(
            String issuingClientId,
            String sourceAudience,
            String sourceSessionId,
            String operation,
            String expiresAt) {
    }
}
