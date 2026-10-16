package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record UpdateDepartmentDTO(
        String name,
        String parentId,
        String status,
        String tenantId,
        Long expectedCtxVersion
) {
    public UpdateDepartmentDTO(String name, String parentId, String status) {
        this(name, parentId, status, null, null);
    }
}
