package com.airagent.iam.admin.vo;

import java.util.List;
import io.swagger.v3.oas.annotations.media.Schema;

/** 平台服务账号建档的目标企业修订与当前可选权限，不授予操作者读取资源的能力。 */
@Schema(description = "服务账号可选权限与目标企业修订")
public record ServiceResourceOptionsVO(String tenantId, Long tenantAuthRevision, List<Option> permissions) {
    /** 可选权限码、显示名及资源归属；普通企业权限的resourceCode为空。 */
    public record Option(String code, String nameZh, String resourceCode) { }
}
