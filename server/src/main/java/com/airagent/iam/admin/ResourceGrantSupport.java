package com.airagent.iam.admin;

import com.airagent.iam.admin.dto.ExpectedContextDTO;
import com.airagent.iam.admin.entity.ResourcePermissionDO;
import com.airagent.iam.admin.mapper.EntitlementMapper;
import com.airagent.iam.admin.mapper.ResourceCatalogMapper;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.web.error.ApiException;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * 角色、成员和机器主体共用的资源写入边界。所有方法由调用方事务包裹。
 * 写入按目录编码、企业 UUID、授权目标的顺序加锁，不从页面声明推导权限。
 */
@Component
public class ResourceGrantSupport {
    private final ResourceCatalogMapper resources;
    private final EntitlementMapper entitlements;

    /** 注入目录与开通权威数据访问组件。 */
    public ResourceGrantSupport(ResourceCatalogMapper resources, EntitlementMapper entitlements) {
        this.resources = resources;
        this.entitlements = entitlements;
    }

    /** 检查打开表单时的会话、企业和代次，缺字段400，已变化409。 */
    public void requireContext(CurrentSession actor, ExpectedContextDTO expected) {
        if (expected == null || expected.sessionId() == null || expected.ctxVersion() == null
                || expected.ctxVersion() < 0) {
            throw ApiException.badRequest("缺少有效的 expected_context");
        }
        UUID sid = AdminSupport.parseUuid(expected.sessionId(), "session_id");
        UUID tid = expected.tenantId() == null ? null : AdminSupport.parseUuid(expected.tenantId(), "tenant_id");
        if (!sid.equals(actor.sessionId()) || !java.util.Objects.equals(tid, actor.currentTenantId())
                || expected.ctxVersion() != actor.ctxVersion()) {
            throw ApiException.contextChanged("表单上下文已变化，请重新打开");
        }
    }

    /** 查询完整权限元数据；未知码整体拒绝，空集合不生成 IN ()。 */
    public List<ResourcePermissionDO> permissions(List<String> codes) {
        if (codes.isEmpty()) return List.of();
        List<ResourcePermissionDO> result = resources.selectPermissionsByCodes(codes);
        if (result.size() != codes.stream().distinct().count()) throw ApiException.badRequest("存在未知权限码");
        return result;
    }

    /**
     * 授权写的串行化点。小型目录的写入统一按编码锁全部目录行，再锁目标企业，
     * 避免角色权限集合在解析后变化造成锁顺序反转；内省和普通读取不取得这些锁。
     * 涉及已有或新增资源配置时，必须携带真实上下文和目标企业修订。
     */
    public void lockWrite(CurrentSession actor, UUID tenant, List<String> codes,
                          ExpectedContextDTO expected, Long revision) {
        resources.lockCatalog();
        if (tenant != null) resources.lockTenants(List.of(tenant));
        boolean resourceWrite = permissions(codes).stream().anyMatch(p -> p.resourceCode() != null);
        if (resourceWrite || expected != null) requireContext(actor, expected);
        if (resourceWrite) {
            if (tenant == null) throw ApiException.conflict("资源权限必须属于明确企业");
            if (revision == null || revision < 0) throw ApiException.badRequest("缺少 expected_tenant_revision");
            Long actual = entitlements.selectTenantAuthRevision(tenant);
            if (actual == null) throw ApiException.notFound("企业不存在");
            if (!revision.equals(actual)) throw ApiException.contextChanged("企业授权修订已变化，请刷新后重试");
        }
    }

    /** 资源中文名；目录不存在时返回 null（不把编码冒充为业务名）。 */
    public String resourceNameZh(String resourceCode) {
        var resource = resources.selectByCode(resourceCode);
        return resource == null ? null : resource.nameZh();
    }

    /** 当前资源可授资格：权限/目录启用、可下放、企业启用且已开通。 */
    public boolean resourceAvailable(UUID tenant, ResourcePermissionDO permission) {
        return permission.grantableToTenants() && resourceInvalidReason(tenant, permission) == null;
    }

    /** 持久化配置的实际失效原因；可下放性与已配置许可的有效性分别计算。 */
    public String resourceInvalidReason(UUID tenant, ResourcePermissionDO permission) {
        if (!"active".equals(permission.status())) return "permission_disabled";
        if (tenant == null) return "not_entitled";
        if (!"active".equals(entitlements.selectTenantStatus(tenant))) return "tenant_suspended";
        var resource = resources.selectByCode(permission.resourceCode());
        if (resource == null || !"active".equals(resource.status())) return "resource_disabled";
        var entitlement = entitlements.selectOne(tenant, permission.resourceCode());
        return entitlement != null && "active".equals(entitlement.status()) ? null : "not_entitled";
    }

    /** 裁决一个新增的企业授权；管理资格只豁免资源读码，不豁免普通权限子集。 */
    public void requireGrantable(CurrentSession actor, UUID tenant, ResourcePermissionDO permission) {
        if (!"tenant".equals(permission.scope()) || !permission.grantableToTenants()) {
            throw ApiException.conflict("权限不可下放企业");
        }
        if (!"active".equals(permission.status())) throw ApiException.conflict("权限已停用");
        if (permission.resourceCode() != null) {
            if (!resourceAvailable(tenant, permission)) throw ApiException.conflict("资源未开通或已停用");
            if (!actor.snapshot().permissions().contains("tenant:resource:grant")
                    && !actor.snapshot().permissions().contains(permission.code())) {
                throw ApiException.forbidden("缺少资源授权管理资格或对应读取权限");
            }
        } else if (!actor.snapshot().hasPlatformRole("platform_super_admin")
                && !actor.snapshot().permissions().contains(permission.code())) {
            throw ApiException.forbidden("不能授予超出自身可授范围的权限");
        }
    }
}
