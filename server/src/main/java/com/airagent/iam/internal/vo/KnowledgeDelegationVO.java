package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 知识只读委托签发响应（{@code iam.knowledge-delegation.v1}）。
 *
 * <p>{@code delegation_token} 只在本响应中出现一次；IAM 只保存其摘要。
 * {@code source} 仅用于可信服务器间核对，不得下发给浏览器或模型。
 *
 * @param schemaVersion   固定 iam.knowledge-delegation.v1
 * @param delegationToken 256 位随机不透明令牌（Bearer）
 * @param tokenType       固定 Bearer
 * @param audience        固定 knowledge
 * @param operation       本次授权的单一操作
 * @param expiresAt       失效时刻（UTC ISO-8601）
 * @param source          源用户/会话/企业/成员/上下文与四项修订
 */
@Schema(name = "KnowledgeDelegationVO", description = "知识库只读委托：单操作、短 TTL、源会话绑定")
public record KnowledgeDelegationVO(
        String schemaVersion,
        String delegationToken,
        String tokenType,
        String audience,
        String operation,
        String expiresAt,
        Source source
) {
    /**
     * 委托来源（非秘密标识与修订）。
     *
     * @param userId         源用户
     * @param sessionId      源会话
     * @param tenantId       当前企业
     * @param membershipId   企业成员关系
     * @param contextVersion 会话上下文代次
     * @param revisions      四项修订
     */
    public record Source(
            String userId,
            String sessionId,
            String tenantId,
            String membershipId,
            long contextVersion,
            RevisionsDTO revisions) {
    }
}
