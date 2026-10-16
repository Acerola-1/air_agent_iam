package com.airagent.iam.admin.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.admin.ResourceGrantSupport;
import com.airagent.iam.admin.dto.CreateResourceDTO;
import com.airagent.iam.admin.dto.ExpectedContextDTO;
import com.airagent.iam.admin.dto.UpdateEntitlementDTO;
import com.airagent.iam.admin.dto.UpdateResourceDTO;
import com.airagent.iam.admin.entity.ResourceCatalogDO;
import com.airagent.iam.admin.entity.ResourcePermissionDO;
import com.airagent.iam.admin.entity.TenantEntitlementDO;
import com.airagent.iam.admin.mapper.EntitlementMapper;
import com.airagent.iam.admin.mapper.ResourceCatalogMapper;
import com.airagent.iam.admin.service.ResourceAdminService;
import com.airagent.iam.admin.vo.EntitlementVO;
import com.airagent.iam.admin.vo.ResourceVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class ResourceAdminServiceImpl implements ResourceAdminService {

    private static final String PERM = "entitlement:manage";
    private static final String TENANT_ROLE_READ = "tenant:role:read";

    private final AdminSupport support;
    private final ResourceCatalogMapper resourceMapper;
    private final EntitlementMapper entitlementMapper;
    private final RequestContextMapper contextMapper;
    private final TransactionTemplate tx;
    private final ResourceGrantSupport grants;

    /** {@inheritDoc} */
    @Override
    public com.airagent.iam.admin.vo.ServiceResourceOptionsVO serviceResourceOptions(CurrentSession actor, String tenantIdRaw) {
        support.requirePermission(actor, "platform:service:write");
        UUID tenant = AdminSupport.parseUuid(tenantIdRaw, "tenant_id");
        return tx.execute(status -> {
            support.setContext(actor.userId(), null, true);
            long revision = tenantRevision(tenant);
            if (!"active".equals(entitlementMapper.selectTenantStatus(tenant))) throw ApiException.conflict("企业已停用");
            var options = resourceMapper.selectMachineOptions(tenant).stream()
                    .map(p -> new com.airagent.iam.admin.vo.ServiceResourceOptionsVO.Option(p.code(), p.nameZh(), p.resourceCode())).toList();
            return new com.airagent.iam.admin.vo.ServiceResourceOptionsVO(tenant.toString(), revision, options);
        });
    }

    public ResourceAdminServiceImpl(AdminSupport support, ResourceCatalogMapper resourceMapper,
                                    EntitlementMapper entitlementMapper,
                                    RequestContextMapper contextMapper, TransactionTemplate tx, ResourceGrantSupport grants) {
        this.support = support;
        this.resourceMapper = resourceMapper;
        this.entitlementMapper = entitlementMapper;
        this.contextMapper = contextMapper;
        this.tx = tx;
        this.grants = grants;
    }

    @Override
    public PageVO<ResourceVO> listResources(CurrentSession actor, String status, Integer limit, String cursor) {
        support.requirePermission(actor, PERM);
        if (status != null && !List.of("active", "disabled").contains(status)) throw ApiException.badRequest("status 不合法");
        int fetch = support.clampLimit(limit);
        String binding = binding(actor, "catalog", status);
        Cursor after = cursor(cursor, binding);
        return tx.execute(status2 -> {
            try {
                support.setContext(actor.userId(), null, true);
                List<ResourceCatalogDO> rows = resourceMapper.selectPage(status, after.sort(), after.code(), fetch + 1);
                return buildResourcePage(rows, fetch, binding);
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    @Override
    public ResourceVO createResource(CurrentSession actor, CreateResourceDTO dto) {
        support.requirePermission(actor, PERM);
        grants.requireContext(actor, dto.expectedContext());
        validateResourceCode(dto.code());
        validateNameZh(dto.nameZh());
        if (dto.permissions() == null || dto.permissions().isEmpty()) {
            throw ApiException.badRequest("至少需要一项权限绑定");
        }
        if (dto.permissions().size() > 32) {
            throw ApiException.badRequest("权限绑定不能超过 32 项");
        }
        List<String> permCodes = new ArrayList<>();
        for (CreateResourceDTO.PermissionBindDTO p : dto.permissions()) {
            validatePermissionBind(dto.code(), p);
            permCodes.add(p.code());
        }
        if (permCodes.size() != permCodes.stream().distinct().count()) {
            throw ApiException.badRequest("权限码不能重复");
        }

        return tx.execute(status -> {
            try {
                support.setContext(actor.userId(), null, true);
                if (resourceMapper.countResourceConflicts(dto.code()) > 0) {
                    throw ApiException.conflict("资源编码已存在");
                }
                if (resourceMapper.countPermissionConflicts(permCodes) > 0) {
                    throw ApiException.conflict("权限码已存在");
                }
                int sort = dto.sort() != null ? dto.sort() : 0;
                resourceMapper.insert(dto.code(), dto.nameZh().trim(), sort, dto.parentCode());
                for (CreateResourceDTO.PermissionBindDTO p : dto.permissions()) {
                    resourceMapper.insertPermission(p.code(), p.nameZh().trim(), dto.code(),
                            Boolean.TRUE.equals(p.grantableToTenants()));
                }
                support.audit(null, actor.userId(), "admin.resource.create", "resource", dto.code(),
                        Map.of("code", dto.code(), "name_zh", dto.nameZh(),
                                "permissions", permCodes));
                return buildResourceVO(resourceMapper.selectByCode(dto.code()));
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    @Override
    public ResourceVO updateResource(CurrentSession actor, String resourceCode, UpdateResourceDTO dto) {
        support.requirePermission(actor, PERM);
        grants.requireContext(actor, dto.expectedContext());
        validateResourceCode(resourceCode);
        if (dto.expectedRevision() == null || dto.expectedRevision() < 1) {
            throw ApiException.badRequest("expected_revision 不合法");
        }
        if (dto.nameZh() != null) {
            validateNameZh(dto.nameZh());
        }
        if (dto.status() != null && !dto.status().equals("active") && !dto.status().equals("disabled")) {
            throw ApiException.badRequest("status 不合法");
        }
        return tx.execute(status -> {
            try {
                support.setContext(actor.userId(), null, true);
                resourceMapper.lockCatalog();
                ResourceCatalogDO existing = resourceMapper.selectByCode(resourceCode);
                if (existing == null) {
                    throw ApiException.notFound("资源不存在");
                }
                int updated = resourceMapper.update(resourceCode, dto.nameZh() == null ? null : dto.nameZh().trim(), dto.sort(),
                        dto.status(), dto.expectedRevision());
                if (updated == 0) {
                    throw ApiException.conflict("修订冲突");
                }
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("code", resourceCode);
                if (dto.nameZh() != null) detail.put("name_zh", dto.nameZh());
                if (dto.sort() != null) detail.put("sort", dto.sort());
                if (dto.status() != null) detail.put("status", dto.status());
                support.audit(null, actor.userId(), "admin.resource.update", "resource", resourceCode, detail);
                return buildResourceVO(resourceMapper.selectByCode(resourceCode));
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    @Override
    public PageVO<EntitlementVO> listTenantEntitlements(CurrentSession actor, String tenantIdStr,
                                                        Integer limit, String cursor) {
        support.requirePermission(actor, PERM);
        UUID tenantId = AdminSupport.parseUuid(tenantIdStr, "tenant_id");
        int fetch = support.clampLimit(limit);
        String binding = binding(actor, "target", tenantId.toString());
        Cursor after = cursor(cursor, binding);
        return tx.execute(status -> {
            try {
                support.setContext(actor.userId(), null, true);
                long tenantRev = tenantRevision(tenantId);
                List<ResourceCatalogDO> allResources = resourceMapper.selectCodePage(after.code(), fetch + 1);
                List<EntitlementVO> items = new ArrayList<>();
                boolean hasMore = allResources.size() > fetch;
                for (int i = 0; i < Math.min(allResources.size(), fetch); i++) {
                    ResourceCatalogDO res = allResources.get(i);
                    TenantEntitlementDO ent = entitlementMapper.selectOne(tenantId, res.code());
                    items.add(buildEntitlementVO(tenantId, res, ent, tenantRev));
                }
                String nextCursor = null;
                if (hasMore && !items.isEmpty()) {
                    nextCursor = encode(binding, 0, allResources.get(fetch - 1).code());
                }
                return new PageVO<>(items, nextCursor);
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    @Override
    public EntitlementVO updateEntitlement(CurrentSession actor, String tenantIdStr,
                                           String resourceCode, UpdateEntitlementDTO dto) {
        support.requirePermission(actor, PERM);
        grants.requireContext(actor, dto.expectedContext());
        UUID tenantId = AdminSupport.parseUuid(tenantIdStr, "tenant_id");
        if (dto.status() == null || (!dto.status().equals("active") && !dto.status().equals("revoked"))) {
            throw ApiException.badRequest("status 不合法");
        }
        if (dto.expectedRevision() == null || dto.expectedRevision() < 0) {
            throw ApiException.badRequest("expected_revision 不合法");
        }
        if (dto.expectedTenantRevision() == null || dto.expectedTenantRevision() < 0) {
            throw ApiException.badRequest("expected_tenant_revision 不合法");
        }

        return tx.execute(status -> {
            try {
                support.setContext(actor.userId(), null, true);
                resourceMapper.lockResourcesAndTenants(List.of(resourceCode), List.of(tenantId));
                resourceMapper.lockTenants(List.of(tenantId));

                ResourceCatalogDO resource = resourceMapper.selectByCode(resourceCode);
                if (resource == null) {
                    throw ApiException.notFound("资源不存在");
                }
                long tenantRev = tenantRevision(tenantId);
                if (tenantRev != dto.expectedTenantRevision()) {
                    throw ApiException.conflict("企业修订冲突");
                }

                TenantEntitlementDO existing = entitlementMapper.selectOne(tenantId, resourceCode);
                long currentRevision = existing != null ? existing.revision() : 0;

                if (existing != null && !existing.revision().equals(dto.expectedRevision().longValue())) {
                    throw ApiException.conflict("修订冲突");
                }
                if (existing == null && dto.expectedRevision() != 0) {
                    throw ApiException.conflict("修订冲突");
                }

                if (existing != null && existing.status().equals(dto.status())) {
                    return buildEntitlementVO(tenantId, resource, existing, tenantRev, false);
                }

                if (dto.status().equals("active")) {
                    if (!"leaf".equals(resource.kind())) throw ApiException.conflict("仅叶子资源可开通");
                    if (!"active".equals(entitlementMapper.selectTenantStatus(tenantId))) throw ApiException.conflict("企业已停用，不能新开通");
                    if ("disabled".equals(resource.status())) {
                        throw ApiException.conflict("资源已停用，不能新开通");
                    }
                }

                if (existing == null) {
                    entitlementMapper.insertIfAbsent(tenantId, resourceCode, dto.status(), actor.userId());
                } else {
                    int updated = entitlementMapper.upsert(tenantId, resourceCode, dto.status(),
                            actor.userId(), dto.expectedRevision(), dto.expectedTenantRevision());
                    if (updated == 0) {
                        throw ApiException.conflict("修订冲突");
                    }
                }

                support.audit(tenantId, actor.userId(), "admin.entitlement.update", "entitlement",
                        tenantId + ":" + resourceCode,
                        Map.of("tenant_id", tenantId.toString(), "resource_code", resourceCode,
                                "status", dto.status(), "from_revision", currentRevision));

                TenantEntitlementDO fresh = entitlementMapper.selectOne(tenantId, resourceCode);
                long newTenantRev = tenantRevision(tenantId);
                return buildEntitlementVO(tenantId, resource, fresh, newTenantRev, true);
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    @Override
    public PageVO<EntitlementVO> listCurrentTenantResources(CurrentSession actor, Integer limit, String cursor) {
        support.requirePermission(actor, TENANT_ROLE_READ);
        UUID tenantId = support.requireCurrentTenant(actor);
        int fetch = support.clampLimit(limit);
        String binding = binding(actor, "current", tenantId.toString());
        Cursor after = cursor(cursor, binding);
        return tx.execute(status -> {
            try {
                support.setContext(actor.userId(), tenantId, false);
                long tenantRev = tenantRevision(tenantId);
                List<TenantEntitlementDO> ents = entitlementMapper.selectByTenant(tenantId, after.code(), fetch + 1);
                List<EntitlementVO> items = new ArrayList<>();
                boolean hasMore = ents.size() > fetch;
                for (int i = 0; i < Math.min(ents.size(), fetch); i++) {
                    TenantEntitlementDO ent = ents.get(i);
                    ResourceCatalogDO res = resourceMapper.selectByCode(ent.resourceCode());
                    if (res != null) {
                        items.add(buildEntitlementVO(tenantId, res, ent, tenantRev));
                    }
                }
                String nextCursor = null;
                if (hasMore && !items.isEmpty()) {
                    nextCursor = encode(binding, 0, ents.get(fetch - 1).resourceCode());
                }
                return new PageVO<>(items, nextCursor);
            } catch (DataAccessException e) {
                throw PgErrorTranslator.toApiException(e);
            }
        });
    }

    private void validateResourceCode(String code) {
        if (code == null || code.length() < 3 || code.length() > 160) {
            throw ApiException.badRequest("资源编码长度不合法");
        }
        if (!code.matches("^[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)+$")) {
            throw ApiException.badRequest("资源编码格式不合法");
        }
    }

    private void validateNameZh(String name) {
        if (name == null || name.isBlank() || name.trim().length() < 1 || name.trim().length() > 100) {
            throw ApiException.badRequest("中文名长度不合法");
        }
    }

    private void validatePermissionBind(String resourceCode, CreateResourceDTO.PermissionBindDTO p) {
        if (p == null) throw ApiException.badRequest("权限绑定不能为 null");
        if (p.code() == null || p.nameZh() == null || p.grantableToTenants() == null) {
            throw ApiException.badRequest("权限绑定字段缺失");
        }
        if (!p.code().startsWith(resourceCode + ":")) {
            throw ApiException.badRequest("权限码必须以资源编码为前缀");
        }
        String action = p.code().substring(resourceCode.length() + 1);
        if (action.isEmpty() || !action.matches("^[a-z][a-z0-9_-]*$")) {
            throw ApiException.badRequest("权限动作段不合法");
        }
        if (resourceCode.startsWith("knowledge:lib:") && !"read".equals(action)) throw ApiException.badRequest("知识库仅支持 read 权限");
        validateNameZh(p.nameZh());
    }

    private ResourceVO buildResourceVO(ResourceCatalogDO row) {
        if (row == null) return null;
        List<ResourcePermissionDO> perms = resourceMapper.selectPermissionsByResource(row.code());
        List<ResourceVO.Bind> binds = perms.stream()
                .map(p -> new ResourceVO.Bind(p.code(), p.nameZh(), p.scope(),
                        p.grantableToTenants(), p.status(), p.resourceCode()))
                .toList();
        return new ResourceVO(row.id().toString(), row.code(), row.nameZh(), row.sort(),
                row.status(), row.kind(), row.parentCode(), row.revision(), binds);
    }

    private PageVO<ResourceVO> buildResourcePage(List<ResourceCatalogDO> rows, int fetch, String binding) {
        boolean hasMore = rows.size() > fetch;
        List<ResourceVO> items = new ArrayList<>();
        for (int i = 0; i < Math.min(rows.size(), fetch); i++) {
            items.add(buildResourceVO(rows.get(i)));
        }
        String nextCursor = null;
        if (hasMore && !items.isEmpty()) {
            nextCursor = encode(binding, rows.get(fetch - 1).sort(), rows.get(fetch - 1).code());
        }
        return new PageVO<>(items, nextCursor);
    }

    private EntitlementVO buildEntitlementVO(UUID tenantId, ResourceCatalogDO res,
                                             TenantEntitlementDO ent, long tenantRev) {
        return buildEntitlementVO(tenantId, res, ent, tenantRev, false);
    }

    private EntitlementVO buildEntitlementVO(UUID tenantId, ResourceCatalogDO res,
                                             TenantEntitlementDO ent, long tenantRev, boolean changed) {
        boolean exists = ent != null;
        String entStatus = exists ? ent.status() : "revoked";
        boolean effective = exists && "active".equals(ent.status()) && "active".equals(res.status())
                && "active".equals(entitlementMapper.selectTenantStatus(tenantId));
        return new EntitlementVO(
                tenantId.toString(),
                res.code(),
                entStatus,
                exists ? ent.revision() : 0,
                exists,
                res.status(),
                effective,
                exists && ent.grantedAt() != null ? ent.grantedAt().toString() : null,
                exists && ent.revokedAt() != null ? ent.revokedAt().toString() : null,
                exists && ent.updatedAt() != null ? ent.updatedAt().toString() : null,
                exists && ent.updatedBy() != null ? ent.updatedBy().toString() : null,
                tenantRev, changed
        );
    }
    /** 不存在企业使用404，不将null拆箱为500。 */
    private long tenantRevision(UUID tenant) {
        Long revision = entitlementMapper.selectTenantAuthRevision(tenant);
        if (revision == null) throw ApiException.notFound("企业不存在");
        return revision;
    }

    /** 游标同时绑定会话上下文、端点、目标企业与过滤条件。 */
    private String binding(CurrentSession actor, String kind, String target) {
        return actor.userId() + ":" + actor.sessionId() + ":" + actor.ctxVersion() + ":" + kind + ":" + target;
    }

    /** 严格解析本域排序游标，拒绝跨作用域、格式错误或错误类型。 */
    private Cursor cursor(String encoded, String binding) {
        if (encoded == null) return new Cursor(null, null);
        try {
            String[] values = support.decodeCursor(encoded).split("\n", -1);
            if (values.length != 4 || !"i1a-v1".equals(values[0]) || !binding.equals(values[1])) throw new IllegalArgumentException();
            int sort = Integer.parseInt(values[2]);
            validateResourceCode(values[3]);
            return new Cursor(sort, values[3]);
        } catch (RuntimeException e) {
            throw ApiException.badRequest("cursor 不合法或不属于当前查询");
        }
    }

    /** 序列化实际排序元组；不以游标授予权限。 */
    private String encode(String binding, int sort, String code) {
        return support.encodeCursor("i1a-v1\n" + binding + "\n" + sort + "\n" + code);
    }

    /** 目录使用sort/code，开通列表使用code（sort为0）。 */
    private record Cursor(Integer sort, String code) { }

}
