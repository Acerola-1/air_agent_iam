package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 企业（租户）HTTP 出参（VO，对外响应模型）。
 *
 * <p>只暴露企业自身的建档事实，不含成员数、部门数等统计，也不含创建人 id。
 * 由企业管理接口直接返回，或作为分页元素出现在 {@code PageVO} 的 items 中。
 *
 * @param id           企业 UUID 文本（主键，服务端生成）
 * @param code         企业编码，全平台唯一，建档后不可修改（2..64 位字母数字与 {@code _ -}）
 * @param name         企业名称，非空且最长 128 字符
 * @param status       企业状态，仅 {@code active} / {@code suspended}；停用后企业内会话在下一次
 *                     权威核验时被判定为不可用，但不会即时清理 Redis 会话键
 * @param authRevision 企业授权代次（初始为 1，状态变更时由触发器 +1）。会话建立时记录基线，
 *                     当前值大于基线即视为授权过期；也是企业 PATCH 的乐观并发基线（expected_revision）
 * @param createdAt    企业建档时间，UTC ISO-8601 文本（由 java.time 默认格式化生成，
 *                     秒为 0 时该位会被省略，故不保证定长）
 * @author Acerola
 */
@Schema(description = "企业（租户）视图")
public record TenantVO(
        @Schema(description = "企业 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "企业编码，全平台唯一且建档后不可改（2..64 位字母数字与 _ -）",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "企业名称，非空且最长 128 字符", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "企业状态；suspended 会让企业内既有会话在下次权威核验时失效",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "suspended"})
        String status,
        @Schema(description = "企业授权代次（初始 1，状态变更时递增）；PATCH 可作为 expected_revision 基线回传",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long authRevision,
        @Schema(description = "建档时间，UTC ISO-8601 文本（秒为 0 时省略该位）", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String createdAt
) {
}
