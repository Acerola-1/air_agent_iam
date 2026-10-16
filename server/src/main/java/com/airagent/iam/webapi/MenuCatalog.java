package com.airagent.iam.webapi;

import com.airagent.iam.auth.AuthoritySnapshot;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * iam-admin 前端菜单目录装配（内部组件，无 HTTP 入口，不访问数据库）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.controller.WebApiAuthController#menus} 在
 * {@code GET /web-api/auth/menus} 内调用，输入为拦截器已核验的 {@link AuthoritySnapshot}；
 * 输出仅描述"前端应展示哪些入口"，权限的<em>最终</em>裁决仍在各管理 Controller/Service 独立进行，
 * 前端隐藏菜单不构成安全边界（菜单只作 UX 提示）。
 *
 * <p>结构与筛选：顶层返回 {@code {application, items}}，{@code application} 固定为
 * {@code iam-admin}。{@code items} 为根列表：先加入子项非空的分组（平台分组恒存在，
 * 企业分组仅在会话已选企业时加入），末尾追加"个人设置"叶子。每个分组 {@code path} 为
 * {@code null}，仅叶子 {@code path} 指向 SPA 路由。分组与叶子的 {@code sort} 字段
 * 为前端排序元数据，本类不做二次排序——按代码写入顺序给出。
 *
 * <p>权限口径：
 * <ul>
 *   <li>平台分组按 {@link AuthoritySnapshot#hasPlatformRole} 判定 {@code platform_super_admin}
 *       与逐项 {@code platform:*:*} 权限码取并集（超管可见全部平台子项）；</li>
 *   <li>企业分组仅按 {@code tenant:*:*} 权限码逐项判定，无跨域角色兜底；</li>
 *   <li>过滤发生在装配末尾——子项 {@code visible=false} 的项不进入父分组 {@code children}，
 *       子项全空的分组整体不进入根列表。</li>
 * </ul>
 *
 * <p>跨企业切换：切换调用
 * {@link com.airagent.iam.auth.service.SessionService#switchTenant(com.airagent.iam.auth.CurrentSession, com.airagent.iam.auth.dto.SwitchTenantDTO)} 后
 * 由数据库 {@code auth_sessions_synchronize_central} 触发器推进 {@code ctx_version} 与
 * {@code base_tenant_revision}/{@code base_membership_revision}，浏览器需重新拉取
 * {@code /me} 与 {@code /menus} 才能看到新企业下的角色/权限集合；本类不缓存快照，
 * 每次调用重新按当前权限码计算。
 *
 * @author Acerola
 */
@Component
public class MenuCatalog {

    /** 平台超管角色码：持有者可见全部平台分组子项。 */
    private static final String PLATFORM_SUPER_ADMIN = "platform_super_admin";

    /**
     * 按会话权限快照构建菜单树。
     *
     * <p>会话快照必须已经过拦截器"Redis 存活 + PG 权威"双检；{@link AuthoritySnapshot#usable()}
     * 为 {@code false} 或 {@code currentTenantId} 为 {@code null} 时企业分组整段省略，
     * 平台分组仍按当前权限码返回。
     *
     * @param snapshot 当前请求已核验的权威快照（提供 {@code permissions}、{@code platform_roles}
     *                 与 {@code current_tenant_id}）；调用方保证非空
     * @return 不可变顶层 Map：{@code application}（字符串 {@code "iam-admin"}）与
     *         {@code items}（{@code List<Map<String, Object>>}，每项含 {@code code/name/path/icon/sort/children}
     *         或 {@code code/name/path/icon/sort/visible}）
     */
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

    /**
     * 装配平台管理分组：超管可见全部子项，其余按 {@code platform:*:*} 权限码逐项判定。
     *
     * <p>子项顺序：平台用户 / 企业与组织 / 平台角色 / 服务账号 / 平台审计。服务账号入口
     * 用 {@code platform:service:write} 作为可见性依据（当前读取与写权限未拆分到更细码）。
     *
     * @param permissions 已去重的权限码集合
     * @param superAdmin  是否持有 {@code platform_super_admin}
     * @return 分组 Map，{@code children} 已过滤仅保留可见项
     */
    private Map<String, Object> platformGroup(Set<String> permissions, boolean superAdmin) {
        List<Map<String, Object>> children = new ArrayList<>();
        children.add(item("platform-users", "平台用户", "/admin/platform/users", "User", 11,
                superAdmin || permissions.contains("platform:user:read")));
        children.add(item("platform-tenants", "企业与组织", "/admin/platform/tenants", "OfficeBuilding", 21,
                superAdmin || permissions.contains("platform:tenant:read")));
        children.add(item("platform-roles", "平台角色", "/admin/platform/roles", "Lock", 31,
                superAdmin || permissions.contains("platform:role:read")));
        children.add(item("platform-resources", "资源目录", "/admin/platform/resources", "Box", 36,
                superAdmin || permissions.contains("entitlement:manage")));
        children.add(item("service-accounts", "服务账号", "/admin/platform/service-accounts", "Key", 41,
                superAdmin || permissions.contains("platform:service:write")));
        children.add(item("platform-audit", "平台审计", "/admin/platform/audit", "Document", 51,
                superAdmin || permissions.contains("platform:audit:read")));
        return group("platform", "平台管理", "Platform", 1, visible(children));
    }

    /**
     * 装配企业管理分组：仅在会话已选企业时构建，按 {@code tenant:*:*} 权限码逐项判定。
     *
     * <p>子项顺序：成员管理 / 部门管理 / 企业角色 / 企业审计。
     *
     * @param permissions 当前企业上下文下已加载的权限码集合（数据库平台+企业角色 UNION 去重）
     * @return 分组 Map，{@code children} 已过滤仅保留可见项
     */
    private Map<String, Object> tenantGroup(Set<String> permissions) {
        List<Map<String, Object>> children = new ArrayList<>();
        children.add(item("tenant-members", "成员管理", "/admin/tenant/members", "UserFilled", 61,
                permissions.contains("tenant:member:read")));
        children.add(item("tenant-departments", "部门管理", "/admin/tenant/departments", "Connection", 71,
                permissions.contains("tenant:department:read")));
        children.add(item("tenant-roles", "企业角色", "/admin/tenant/roles", "Avatar", 81,
                permissions.contains("tenant:role:read")));
        children.add(item("tenant-resources", "企业资源", "/admin/tenant/resources", "Box", 86,
                permissions.contains("tenant:role:read")));
        children.add(item("tenant-audit", "企业审计", "/admin/tenant/audit", "Tickets", 91,
                permissions.contains("tenant:audit:read")));
        return group("tenant", "企业管理", "Shop", 2, visible(children));
    }

    /**
     * 过滤出 {@code visible=true} 的子项；用 {@code Boolean.TRUE.equals} 防御性判空。
     *
     * @param items 待过滤的子项列表
     * @return 保留原有顺序的可见项列表
     */
    private List<Map<String, Object>> visible(List<Map<String, Object>> items) {
        return items.stream().filter(i -> Boolean.TRUE.equals(i.get("visible"))).toList();
    }

    /**
     * 装配分组节点：分组本身无跳转路径，{@code path} 恒为 {@code null}。
     *
     * @param code     分组稳定标识（{@code platform} / {@code tenant}）
     * @param name     分组显示名
     * @param icon     前端图标名（Element Plus 图标组件标识）
     * @param sort     前端排序元数据
     * @param children 已过滤的可见子项
     * @return 保序 Map（{@code LinkedHashMap}）
     */
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

    /**
     * 装配叶子节点：即使 {@code visible=false} 也会被写入，最终由
     * {@link #visible(List)} 过滤，因此调用方可放心把权限判定结果直接放这里。
     *
     * @param code    叶子稳定标识
     * @param name    叶子显示名
     * @param path    SPA 路由路径
     * @param icon    前端图标名
     * @param sort    前端排序元数据
     * @param visible 是否对当前会话可见
     * @return 保序 Map（{@code LinkedHashMap}）
     */
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
