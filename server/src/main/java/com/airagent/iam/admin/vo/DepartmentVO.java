package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 部门 HTTP 出参（VO，对外响应模型）。
 *
 * <p>响应是扁平的单条部门事实，服务端不组装树：父级仅以 {@code parentId} 文本给出，
 * 由前端按 parentId 归组渲染。列表接口按 id 升序返回，不裁剪停用部门，也不含时间戳字段。
 *
 * @param id       部门 UUID 文本（主键，服务端生成）
 * @param tenantId 所属企业 UUID 文本，恒等于会话当前企业上下文（部门不跨企业可见）
 * @param parentId 上级部门 UUID 文本；{@code null} 表示顶级部门。父级必须属于同一企业
 *                 （同租户复合外键约束），且层级不允许成环（数据库触发器兜底）
 * @param code     部门编码，1..64 位字母数字与 {@code _ -}，企业内唯一
 * @param name     部门名称，最长 128 字符；建部门时强制非空，改部门时未做非空校验（省略即保持原值）
 * @param status   部门状态，仅 {@code active} / {@code disabled}；变更不推进任何授权代次，
 *                 也不参与会话权威判定（部门明细不影响登录态）
 * @author Acerola
 */
@Schema(description = "部门视图（扁平结构，父子关系仅以 parentId 表达）")
public record DepartmentVO(
        @Schema(description = "部门 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "所属企业 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String tenantId,
        @Schema(description = "上级部门 UUID；为 null 表示顶级部门", format = "uuid")
        String parentId,
        @Schema(description = "部门编码，企业内唯一（1..64 位字母数字与 _ -）", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "部门名称，最长 128 字符（创建时必填且非空）", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "部门状态；变更不影响会话授权代次", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"active", "disabled"})
        String status
) {
}
