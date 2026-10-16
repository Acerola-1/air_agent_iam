package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record CreateDepartmentDTO(
        String code,
        String name,
        String parentId,
        String tenantId,
        Long expectedCtxVersion
) {
    public CreateDepartmentDTO(String code, String name, String parentId) {
        this(code, name, parentId, null, null);
    }
}
