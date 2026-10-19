package com.airagent.iam.ops;

import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.ops.entity.OpsBusinessResourceDO;
import com.airagent.iam.ops.entity.OpsEntitlementDO;
import com.airagent.iam.ops.entity.OpsLegacyPermissionDO;
import com.airagent.iam.ops.entity.OpsMembershipDO;
import com.airagent.iam.ops.entity.OpsPermissionDO;
import com.airagent.iam.ops.entity.OpsRoleDO;
import com.airagent.iam.ops.entity.OpsTenantDO;
import com.airagent.iam.ops.entity.OpsUserDO;
import com.airagent.iam.ops.mapper.OpsMapper;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * 一次性 IAM 运维编排：root 显式授权、旧授权清点/清理与发布复验。
 *
 * <p>安全边界：
 * <ul>
 *   <li>root 必须按精确 UUID 定位，并匹配期望账号、处于 active；不存在/停用/账号不符时写前失败；</li>
 *   <li>每个目标企业一个独立事务，包含开通、成员、角色、授权、审计与修订推进；
 *       任一企业失败只回滚该企业，已提交结果如实记录；</li>
 *   <li>不修改口令、不启用停用主体、不创建替身、不使用用户名旁路；</li>
 *   <li>只输出对象 ID、版本、计数和状态，不输出任何口令/令牌/连接串。</li>
 * </ul>
 *
 * @author Acerola
 */
public class OpsService {

    /** root 专用企业角色编码。 */
    static final String ROOT_ROLE_CODE = "tenant_agent_test_admin";
    /** root 专用企业角色名称。 */
    static final String ROOT_ROLE_NAME = "Agent 测试管理员";
    /** root 专用企业角色说明。 */
    static final String ROOT_ROLE_DESCRIPTION = "root 专用：Agent 业务使用与运营查看（一次性显式配置）";
    /** Agent 运营查看所需精确权限码。 */
    static final List<String> AGENT_VIEW_PERMISSIONS = List.of(
            "agent:operations:read", "agent:metrics:read", "agent:content:read");
    /** 本阶段明确清理的旧 Agent MCP 权限码。 */
    static final List<String> LEGACY_AGENT_CODES = List.of(
            "enterprise:mcp", "mcp:binding:read", "mcp:binding:manage");
    /** 旧模型若存在则必须报告的专用表；IAM 实际未创建。 */
    static final List<String> LEGACY_TABLES = List.of(
            "iam.mcp_identity_bindings", "iam.mcp_bindings", "iam.agent_skill_permissions",
            "iam.skill_permissions", "iam.agent_business_grants");

    private final OpsMapper mapper;
    private final RequestContextMapper contextMapper;
    private final AdminEventMapper eventMapper;
    private final TransactionTemplate tx;
    private final ObjectMapper json;
    private final OpsProperties props;

    public OpsService(OpsMapper mapper, RequestContextMapper contextMapper,
                      AdminEventMapper eventMapper, TransactionTemplate tx,
                      ObjectMapper json, OpsProperties props) {
        this.mapper = mapper;
        this.contextMapper = contextMapper;
        this.eventMapper = eventMapper;
        this.tx = tx;
        this.json = json;
        this.props = props;
    }

    // ---------------------------------------------------------------- root 授权

    /** 只读计划：列出每个目标企业的现状与将执行的动作，不写任何行。 */
    public Map<String, Object> planRootAccess() {
        OpsUserDO root = requireRoot();
        List<OpsTenantDO> tenants = resolveTenants(false);
        return inspectAll(root, tenants, false);
    }

    /** 显式执行：写前完成全部冲突检查；每个企业独立事务提交。 */
    public Map<String, Object> applyRootAccess() {
        OpsUserDO root = requireRoot();
        List<OpsTenantDO> tenants = resolveTenants(true);
        Map<String, Object> preflight = inspectAll(root, tenants, true);
        if (!Boolean.TRUE.equals(preflight.get("ok"))) {
            return preflight;
        }
        List<Map<String, Object>> results = new ArrayList<>();
        for (OpsTenantDO tenant : tenants) {
            try {
                results.add(tx.execute(status -> applyTenant(root, tenant)));
            } catch (RuntimeException e) {
                Map<String, Object> failed = new LinkedHashMap<>();
                failed.put("tenant_id", tenant.id().toString());
                failed.put("tenant_code", tenant.code());
                failed.put("tenant_name", tenant.name());
                failed.put("status", "failed");
                failed.put("message", safeMessage(e));
                results.add(failed);
            }
        }
        Map<String, Object> out = base("apply");
        out.put("root_user_id", root.id().toString());
        out.put("root_account", root.account());
        out.put("tenants", results);
        out.put("summary", summarize(results));
        return out;
    }

    /** 复验：只读核对每个目标企业的成员、角色、开通与权限。 */
    public Map<String, Object> verifyRootAccess() {
        OpsUserDO root = requireRoot();
        List<OpsTenantDO> tenants = resolveTenants(false);
        Map<String, Object> out = inspectAll(root, tenants, false);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) out.get("tenants");
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String tenant = row.get("tenant_code") + "(" + row.get("tenant_id") + ")";
            if (!"ready".equals(row.get("status"))) {
                failures.add(tenant + ": " + row.get("conflicts"));
                continue;
            }
            if (!"reuse".equals(row.get("membership_action"))) {
                failures.add(tenant + ": 缺少 root 有效成员关系");
            }
            if (!"reuse".equals(row.get("role_action"))) {
                failures.add(tenant + ": 缺少生效的 " + ROOT_ROLE_CODE + " 角色");
            }
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> entitlements = (List<Map<String, Object>>) row.get("entitlements");
            for (Map<String, Object> ent : entitlements) {
                if (!"unchanged".equals(ent.get("action"))) {
                    failures.add(tenant + ": 业务未开通 " + ent.get("resource_code"));
                }
            }
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> permissions = (List<Map<String, Object>>) row.get("permissions");
            for (Map<String, Object> perm : permissions) {
                if (!Boolean.TRUE.equals(perm.get("configured"))) {
                    failures.add(tenant + ": 角色缺少权限 " + perm.get("code"));
                }
            }
            if (!Boolean.TRUE.equals(row.get("membership_role_linked"))) {
                failures.add(tenant + ": 成员未关联测试角色");
            }
        }
        out.put("command", "verify");
        out.put("ok", failures.isEmpty());
        out.put("failures", failures);
        return out;
    }

    private OpsUserDO requireRoot() {
        if (props.getRootUserId() == null || props.getRootUserId().isBlank()) {
            throw new OpsConflictException("缺少 --iam.ops.root-user-id（必须为现有 root 的精确 UUID）");
        }
        UUID rootId = parseUuid(props.getRootUserId(), "root_user_id");
        OpsUserDO root = tx.execute(status -> {
            setContext(null, null, true);
            return mapper.selectUser(rootId);
        });
        if (root == null) {
            throw new OpsConflictException("root 用户不存在: " + rootId);
        }
        if (!"active".equals(root.status())) {
            throw new OpsConflictException("root 用户已停用，拒绝静默启用: " + root.account());
        }
        if (!props.getExpectedAccount().equals(root.account())) {
            throw new OpsConflictException("root 账号不匹配：期望 " + props.getExpectedAccount()
                    + "，实际 " + root.account());
        }
        return root;
    }

    private List<OpsTenantDO> resolveTenants(boolean apply) {
        if (props.getTenantIds() != null && !props.getTenantIds().isBlank()) {
            LinkedHashSet<UUID> ids = new LinkedHashSet<>();
            for (String raw : props.getTenantIds().split(",")) {
                if (!raw.isBlank()) {
                    ids.add(parseUuid(raw.trim(), "tenant_id"));
                }
            }
            if (ids.isEmpty()) {
                throw new OpsConflictException("--iam.ops.tenant-ids 未包含有效 UUID");
            }
            return tx.execute(status -> {
                setContext(null, null, true);
                List<OpsTenantDO> result = new ArrayList<>();
                for (UUID id : ids) {
                    OpsTenantDO tenant = mapper.selectTenant(id);
                    if (tenant == null) {
                        throw new OpsConflictException("目标企业不存在: " + id);
                    }
                    if (!"active".equals(tenant.status())) {
                        throw new OpsConflictException("目标企业已停用: " + tenant.code());
                    }
                    result.add(tenant);
                }
                return result;
            });
        }
        if (apply && !props.isAllActiveTenants()) {
            throw new OpsConflictException(
                    "apply 必须显式给出 --iam.ops.tenant-ids 或 --iam.ops.all-active-tenants=true");
        }
        return tx.execute(status -> {
            setContext(null, null, true);
            return mapper.selectActiveTenants();
        });
    }

    private Map<String, Object> inspectAll(OpsUserDO root, List<OpsTenantDO> tenants, boolean forApply) {
        List<OpsBusinessResourceDO> businesses = tx.execute(status -> {
            setContext(null, null, true);
            return mapper.selectActiveBusinessResources();
        });
        List<String> required = requiredPermissionCodes(businesses);
        List<Map<String, Object>> rows = tx.execute(status -> {
            setContext(root.id(), null, true);
            List<Map<String, Object>> out = new ArrayList<>();
            for (OpsTenantDO tenant : tenants) {
                out.add(inspectTenant(root, tenant, businesses, required));
            }
            return out;
        });
        boolean ok = rows.stream().allMatch(row -> "ready".equals(row.get("status"))
                || "applied".equals(row.get("status")) || "unchanged".equals(row.get("status")));
        Map<String, Object> out = base(forApply ? "apply-preflight" : "plan");
        out.put("root_user_id", root.id().toString());
        out.put("root_account", root.account());
        out.put("business_resources", businesses.stream().map(r -> Map.of(
                "code", r.code(), "name_zh", r.nameZh(), "sort", r.sort())).toList());
        out.put("required_permission_codes", required);
        out.put("tenants", rows);
        out.put("ok", ok);
        return out;
    }

    private Map<String, Object> inspectTenant(OpsUserDO root, OpsTenantDO tenant,
                                               List<OpsBusinessResourceDO> businesses,
                                               List<String> required) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tenant_id", tenant.id().toString());
        row.put("tenant_code", tenant.code());
        row.put("tenant_name", tenant.name());
        List<String> conflicts = new ArrayList<>();
        if (!"active".equals(tenant.status())) {
            conflicts.add("企业已停用");
        }

        OpsMembershipDO membership = mapper.selectMembership(tenant.id(), root.id());
        String membershipAction;
        if (membership == null) {
            membershipAction = "create";
            row.put("membership_id", null);
        } else if ("active".equals(membership.status())) {
            membershipAction = "reuse";
            row.put("membership_id", membership.id().toString());
            row.put("membership_revision", membership.revision());
        } else {
            membershipAction = "conflict";
            conflicts.add("root 成员关系已停用（不静默启用）");
            row.put("membership_id", membership.id().toString());
        }
        row.put("membership_action", membershipAction);

        OpsRoleDO role = mapper.selectTenantRole(tenant.id(), ROOT_ROLE_CODE);
        String roleAction;
        if (role == null) {
            roleAction = "create";
        } else if (role.builtin()) {
            roleAction = "conflict";
            conflicts.add("同名角色为内置角色，拒绝修改");
        } else if (!"active".equals(role.status())) {
            roleAction = "conflict";
            conflicts.add("同名企业角色已停用（不静默启用）");
        } else {
            roleAction = "reuse";
        }
        row.put("role_id", role == null ? null : role.id().toString());
        row.put("role_action", roleAction);

        Map<String, OpsPermissionDO> perms = new LinkedHashMap<>();
        for (OpsPermissionDO p : mapper.selectPermissionsByCodes(required)) {
            perms.put(p.code(), p);
        }
        for (String code : required) {
            OpsPermissionDO p = perms.get(code);
            if (p == null) {
                conflicts.add("缺少权限定义: " + code);
            } else if (!"active".equals(p.status())) {
                conflicts.add("权限已停用: " + code);
            }
        }

        List<Map<String, Object>> entitlementRows = new ArrayList<>();
        for (OpsBusinessResourceDO business : businesses) {
            OpsEntitlementDO ent = mapper.selectEntitlement(tenant.id(), business.code());
            String action;
            String status;
            if (ent == null) {
                action = "activate";
                status = "missing";
            } else if ("active".equals(ent.status())) {
                action = "unchanged";
                status = "active";
            } else {
                action = "activate";
                status = ent.status();
            }
            entitlementRows.add(Map.of(
                    "resource_code", business.code(),
                    "resource_name_zh", business.nameZh(),
                    "status", status,
                    "action", action));
        }
        row.put("entitlements", entitlementRows);

        List<String> configured = role == null ? List.of() : mapper.selectRolePermissionCodes(role.id());
        List<Map<String, Object>> permissionRows = new ArrayList<>();
        for (String code : required) {
            boolean present = configured.contains(code);
            permissionRows.add(Map.of("code", code, "configured", present,
                    "action", present ? "unchanged" : "add"));
        }
        row.put("permissions", permissionRows);
        boolean linked = role != null && membership != null
                && mapper.countMembershipRole(membership.id(), role.id()) > 0;
        row.put("membership_role_linked", linked);
        row.put("membership_role_action", linked ? "unchanged" : "add");
        row.put("tenant_auth_revision", tenant.authRevision());
        row.put("status", conflicts.isEmpty() ? "ready" : "conflict");
        row.put("conflicts", conflicts);
        return row;
    }

    private Map<String, Object> applyTenant(OpsUserDO root, OpsTenantDO tenant) {
        setContext(root.id(), tenant.id(), true);
        OpsTenantDO locked = mapper.selectTenantForUpdate(tenant.id());
        if (locked == null || !"active".equals(locked.status())) {
            throw new OpsConflictException("企业已停用: " + tenant.code());
        }

        List<OpsBusinessResourceDO> businesses = mapper.selectActiveBusinessResources();
        List<String> required = requiredPermissionCodes(businesses);
        Map<String, OpsPermissionDO> perms = new LinkedHashMap<>();
        for (OpsPermissionDO p : mapper.selectPermissionsByCodes(required)) {
            if (!"active".equals(p.status())) {
                throw new OpsConflictException("权限已停用: " + p.code());
            }
            perms.put(p.code(), p);
        }
        if (perms.size() != required.size()) {
            throw new OpsConflictException("当前 Agent 业务或查看权限定义不完整");
        }

        OpsMembershipDO membership = mapper.selectMembershipForUpdate(tenant.id(), root.id());
        boolean membershipCreated = false;
        if (membership == null) {
            UUID id = mapper.insertMembership(tenant.id(), root.id(), root.id());
            membership = new OpsMembershipDO(id, "active", 1);
            membershipCreated = true;
        } else if (!"active".equals(membership.status())) {
            throw new OpsConflictException("root 成员关系已停用，拒绝静默启用");
        }

        OpsRoleDO role = mapper.selectTenantRoleForUpdate(tenant.id(), ROOT_ROLE_CODE);
        boolean roleCreated = false;
        if (role == null) {
            UUID id = mapper.insertTenantRole(tenant.id(), ROOT_ROLE_CODE, ROOT_ROLE_NAME,
                    ROOT_ROLE_DESCRIPTION);
            role = new OpsRoleDO(id, ROOT_ROLE_CODE, false, "active");
            roleCreated = true;
        } else if (role.builtin() || !"active".equals(role.status())) {
            throw new OpsConflictException("同名企业角色不可用");
        }

        List<String> entitlementsActivated = new ArrayList<>();
        for (OpsBusinessResourceDO business : businesses) {
            if (mapper.activateEntitlement(tenant.id(), business.code(), root.id()) > 0) {
                entitlementsActivated.add(business.code());
            }
        }

        List<String> configured = mapper.selectRolePermissionCodes(role.id());
        List<String> permissionsAdded = new ArrayList<>();
        for (String code : required) {
            if (!configured.contains(code)) {
                if (mapper.insertRolePermission(role.id(), perms.get(code).id(), root.id()) > 0) {
                    permissionsAdded.add(code);
                }
            }
        }

        boolean membershipRoleAdded = false;
        if (mapper.countMembershipRole(membership.id(), role.id()) == 0) {
            membershipRoleAdded = mapper.insertMembershipRole(tenant.id(), membership.id(),
                    role.id(), root.id()) > 0;
        }

        boolean changed = membershipCreated || roleCreated || !entitlementsActivated.isEmpty()
                || !permissionsAdded.isEmpty() || membershipRoleAdded;
        if (changed) {
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("root_user_id", root.id().toString());
            detail.put("role_code", ROOT_ROLE_CODE);
            detail.put("membership_created", membershipCreated);
            detail.put("role_created", roleCreated);
            detail.put("entitlements_activated", entitlementsActivated);
            detail.put("permissions_added", permissionsAdded);
            detail.put("membership_role_added", membershipRoleAdded);
            eventMapper.insertAudit(tenant.id(), root.id(), "admin.root_access.apply",
                    "tenant", tenant.id().toString(), json.writeValueAsString(detail), "iam-ops");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tenant_id", tenant.id().toString());
        result.put("tenant_code", tenant.code());
        result.put("tenant_name", tenant.name());
        result.put("status", changed ? "applied" : "unchanged");
        result.put("changed", changed);
        result.put("membership_id", membership.id().toString());
        result.put("membership_created", membershipCreated);
        result.put("role_id", role.id().toString());
        result.put("role_created", roleCreated);
        result.put("entitlements_activated", entitlementsActivated);
        result.put("permissions_added", permissionsAdded);
        result.put("membership_role_added", membershipRoleAdded);
        result.put("tenant_auth_revision", mapper.selectTenantAuthRevision(tenant.id()));
        result.put("membership_revision", mapper.selectMembershipRevision(membership.id()));
        return result;
    }

    // ---------------------------------------------------------------- 旧授权清点/清理

    /** 只读清点：旧权限定义、角色/服务账号关联与专用表是否存在。 */
    public Map<String, Object> inventoryLegacyGrants() {
        Map<String, Object> out = tx.execute(status -> {
            setContext(null, null, true);
            return inventoryInTx();
        });
        out.put("command", "inventory");
        return out;
    }

    /** 显式清理：在单一事务内删除命中定义及关联，推进修订并审计。 */
    public Map<String, Object> cleanupLegacyGrants() {
        Map<String, Object> out = tx.execute(status -> {
            setContext(null, null, true);
            Map<String, Object> result = inventoryInTx();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> permissions = (List<Map<String, Object>>) result.get("permissions");
            List<Map<String, Object>> deleted = new ArrayList<>();
            for (Map<String, Object> row : permissions) {
                if (!Boolean.TRUE.equals(row.get("exists"))) {
                    continue;
                }
                UUID id = UUID.fromString((String) row.get("id"));
                String code = (String) row.get("code");
                int roleEdges = mapper.deleteRolePermissionsByPermission(id);
                int serviceEdges = mapper.deleteServiceAccountPermissionsByPermission(id);
                int definitions = mapper.deletePermission(id);
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("code", code);
                detail.put("role_edges_deleted", roleEdges);
                detail.put("service_account_edges_deleted", serviceEdges);
                detail.put("definitions_deleted", definitions);
                eventMapper.insertAudit(null, null, "admin.legacy_agent_grants.cleanup",
                        "permission", code, json.writeValueAsString(detail), "iam-ops");
                Map<String, Object> item = new LinkedHashMap<>(row);
                item.put("role_edges_deleted", roleEdges);
                item.put("service_account_edges_deleted", serviceEdges);
                item.put("definition_deleted", definitions > 0);
                deleted.add(item);
            }
            result.put("deleted", deleted);
            result.put("deleted_count", deleted.size());
            return result;
        });
        out.put("command", "cleanup-apply");
        return out;
    }

    private Map<String, Object> inventoryInTx() {
        List<OpsLegacyPermissionDO> rows = mapper.selectLegacyPermissions(LEGACY_AGENT_CODES);
        Map<String, OpsLegacyPermissionDO> found = new LinkedHashMap<>();
        for (OpsLegacyPermissionDO row : rows) {
            found.put(row.code(), row);
        }
        List<Map<String, Object>> permissions = new ArrayList<>();
        int totalRole = 0;
        int totalSa = 0;
        for (String code : LEGACY_AGENT_CODES) {
            OpsLegacyPermissionDO row = found.get(code);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("code", code);
            if (row == null) {
                item.put("exists", false);
                item.put("role_edges", 0);
                item.put("service_account_edges", 0);
            } else {
                item.put("exists", true);
                item.put("id", row.id().toString());
                item.put("scope", row.scope());
                item.put("status", row.status());
                item.put("role_edges", row.roleEdges());
                item.put("service_account_edges", row.serviceAccountEdges());
                totalRole += row.roleEdges();
                totalSa += row.serviceAccountEdges();
            }
            permissions.add(item);
        }
        List<String> tables = mapper.selectExistingTables(LEGACY_TABLES);
        Map<String, Object> out = base("inventory");
        out.put("target_codes", LEGACY_AGENT_CODES);
        out.put("permissions", permissions);
        out.put("total_role_edges", totalRole);
        out.put("total_service_account_edges", totalSa);
        out.put("dedicated_tables_checked", LEGACY_TABLES);
        out.put("dedicated_tables_present", tables);
        out.put("note", "通用 permissions/roles/role_permissions 不是旧专用表，不进入删除范围；"
                + "菜单与种子引用需配合源码扫描，见交付报告。");
        return out;
    }

    // ---------------------------------------------------------------- 辅助

    private List<String> requiredPermissionCodes(List<OpsBusinessResourceDO> businesses) {
        List<String> codes = new ArrayList<>();
        for (OpsBusinessResourceDO business : businesses) {
            codes.add(business.code() + ":use");
        }
        codes.addAll(AGENT_VIEW_PERMISSIONS);
        return codes;
    }

    private Map<String, Object> base(String command) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("generated_at", OffsetDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        out.put("command", command);
        out.put("no_backup", true);
        return out;
    }

    private Map<String, Object> summarize(List<Map<String, Object>> results) {
        int applied = 0;
        int unchanged = 0;
        int failed = 0;
        for (Map<String, Object> row : results) {
            String status = String.valueOf(row.get("status"));
            switch (status) {
                case "applied" -> applied++;
                case "unchanged" -> unchanged++;
                default -> failed++;
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total", results.size());
        summary.put("applied", applied);
        summary.put("unchanged", unchanged);
        summary.put("failed", failed);
        summary.put("ok", failed == 0);
        return summary;
    }

    private void setContext(UUID userId, UUID tenantId, boolean platform) {
        contextMapper.setContext(userId, tenantId, platform);
    }

    private static UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new OpsConflictException(field + " 不是合法 UUID: " + value);
        }
    }

    private static String safeMessage(RuntimeException e) {
        String message = e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : message;
    }
}
