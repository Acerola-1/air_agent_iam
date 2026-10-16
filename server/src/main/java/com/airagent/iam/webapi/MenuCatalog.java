package com.airagent.iam.webapi;

import com.airagent.iam.auth.AuthoritySnapshot;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * iam-admin 菜单目录：后端按当前实时有效权限给出，菜单仅 UX 提示，
 * 每个端点仍独立裁决；平台超级管理员可见全部平台分组。
 */
@Component
public class MenuCatalog {

    private static final String PLATFORM_SUPER_ADMIN = "platform_super_admin";

    public Map<String, Object> build(AuthoritySnapshot snapshot) {
        Set<String> permissions = Set.copyOf(snapshot.permissions());
        boolean superAdmin = snapshot.hasPlatformRole(PLATFORM_SUPER_ADMIN);
        boolean tenantSelected = snapshot.usable() && snapshot.currentTenantId() != null;

        List<Map<String, Object>> groups = new ArrayList<>();
        groups.add(platformGroup(permissions, superAdmin));
        if (tenantSelected) {
            groups.add(tenantGroup(permissions));
        }

        List<Map<String, Object>> roots = new ArrayList<>();
        roots.addAll(groups.stream().filter(g -> !((List<?>) g.get("children")).isEmpty()).toList());
        roots.add(item("profile", "个人设置", "/profile", "UserFilled", 90, true));
        return Map.of("application", "iam-admin", "items", roots);
    }

    private Map<String, Object> platformGroup(Set<String> permissions, boolean superAdmin) {
        List<Map<String, Object>> children = new ArrayList<>();
        children.add(item("platform-users", "平台用户", "/admin/platform/users", "User", 11,
                superAdmin || permissions.contains("platform:user:read")));
        children.add(item("platform-tenants", "企业与组织", "/admin/platform/tenants", "OfficeBuilding", 21,
                superAdmin || permissions.contains("platform:tenant:read")));
        children.add(item("platform-roles", "平台角色", "/admin/platform/roles", "Lock", 31,
                superAdmin || permissions.contains("platform:role:read")));
        children.add(item("service-accounts", "服务账号", "/admin/platform/service-accounts", "Key", 41,
                superAdmin || permissions.contains("platform:service:write")));
        children.add(item("platform-audit", "平台审计", "/admin/platform/audit", "Document", 51,
                superAdmin || permissions.contains("platform:audit:read")));
        return group("platform", "平台管理", "Platform", 1, visible(children));
    }

    private Map<String, Object> tenantGroup(Set<String> permissions) {
        List<Map<String, Object>> children = new ArrayList<>();
        children.add(item("tenant-members", "成员管理", "/admin/tenant/members", "UserFilled", 61,
                permissions.contains("tenant:member:read")));
        children.add(item("tenant-departments", "部门管理", "/admin/tenant/departments", "Connection", 71,
                permissions.contains("tenant:department:read")));
        children.add(item("tenant-roles", "企业角色", "/admin/tenant/roles", "Avatar", 81,
                permissions.contains("tenant:role:read")));
        children.add(item("tenant-audit", "企业审计", "/admin/tenant/audit", "Tickets", 91,
                permissions.contains("tenant:audit:read")));
        return group("tenant", "企业管理", "Shop", 2, visible(children));
    }

    private List<Map<String, Object>> visible(List<Map<String, Object>> items) {
        return items.stream().filter(i -> Boolean.TRUE.equals(i.get("visible"))).toList();
    }

    private Map<String, Object> group(String code, String name, String icon, int sort,
                                      List<Map<String, Object>> children) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("code", code);
        map.put("name", name);
        map.put("path", null);
        map.put("icon", icon);
        map.put("sort", sort);
        map.put("children", children);
        return map;
    }

    private Map<String, Object> item(String code, String name, String path, String icon,
                                     int sort, boolean visible) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("code", code);
        map.put("name", name);
        map.put("path", path);
        map.put("icon", icon);
        map.put("sort", sort);
        map.put("visible", visible);
        return map;
    }
}
