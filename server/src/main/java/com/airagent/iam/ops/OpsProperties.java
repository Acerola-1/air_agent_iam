package com.airagent.iam.ops;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 一次性运维命令参数（只读计划、显式执行、旧授权清点/清理与复验）。
 *
 * <p>参数仅描述目标对象与非秘密输出位置；不含任何口令、令牌或数据库凭据。
 * 未显式给出 {@code command} 时拒绝执行，避免以空参数触发写操作。
 *
 * @author Acerola
 */
@ConfigurationProperties(prefix = "iam.ops")
public class OpsProperties {

    /** 命令：plan/apply/verify/inventory/cleanup-plan/cleanup-apply。 */
    private String command;
    /** 现有 root 用户精确 UUID（plan/apply/verify 必填）。 */
    private String rootUserId;
    /** 期望的 root 登录账号，默认 root；用于防止 UUID 指错主体。 */
    private String expectedAccount = "root";
    /** 目标企业 UUID 列表，逗号分隔；apply 必须显式给出或 all-active-tenants=true。 */
    private String tenantIds;
    /** apply 时是否覆盖执行时全部 active 企业；plan/verify 默认按全部 active 企业只读展示。 */
    private boolean allActiveTenants;
    /** 非秘密结果 JSON 输出文件路径；为空只写标准输出。 */
    private String output;

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public String getRootUserId() {
        return rootUserId;
    }

    public void setRootUserId(String rootUserId) {
        this.rootUserId = rootUserId;
    }

    public String getExpectedAccount() {
        return expectedAccount;
    }

    public void setExpectedAccount(String expectedAccount) {
        this.expectedAccount = expectedAccount;
    }

    public String getTenantIds() {
        return tenantIds;
    }

    public void setTenantIds(String tenantIds) {
        this.tenantIds = tenantIds;
    }

    public boolean isAllActiveTenants() {
        return allActiveTenants;
    }

    public void setAllActiveTenants(boolean allActiveTenants) {
        this.allActiveTenants = allActiveTenants;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }
}
