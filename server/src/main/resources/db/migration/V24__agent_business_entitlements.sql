-- Agent 当前三项业务目录、唯一使用权限与 Agent 必要查看权限的幂等登记。
-- 复用 V20 通用 resource_catalog / tenant_entitlements / permissions，不新增业务关系表。
--
-- 新增业务时的固定步骤（不得跳步，也不得自动授予既有企业或 root）：
--   1. 在后续迁移中登记一个 agent:business:<code> 叶子资源与同前缀 :use 权限；
--   2. 在共同契约 business-authorization-contract.md 冻结稳定编码与中文名；
--   3. 由平台管理员在企业资源开通中显式开通；
--   4. 由企业管理员在本企业独有角色中显式授予使用码；
--   5. 平台角色、全局企业模板与任何身份都不会因前缀或管理员身份自动获得。

-- V21 起 resource_catalog 为 FORCE RLS；迁移写目录需显式平台上下文（事务级）。
SELECT set_config('app.is_platform', 'on', true);

-- ===========================================================================
-- 1. 三项稳定业务资源（中文名、启停、排序；可下放企业）
-- ===========================================================================

INSERT INTO iam.resource_catalog (code, name_zh, sort, status, kind, parent_code)
VALUES
  ('agent:business:basic-qa',            '基础问答', 501, 'active', 'leaf', 'agent'),
  ('agent:business:data-analysis',       '数据分析', 502, 'active', 'leaf', 'agent'),
  ('agent:business:intelligent-tracing', '智能溯源', 503, 'active', 'leaf', 'agent')
ON CONFLICT (code) DO NOTHING;

-- ===========================================================================
-- 2. 每项业务唯一使用权限（企业可下放，精确匹配，不使用通配）
-- ===========================================================================

INSERT INTO iam.permissions (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort)
VALUES
  ('01930000-0000-4000-8000-000000000501', 'agent:business:basic-qa:use',
   '使用基础问答', 'tenant', true, 'agent:business:basic-qa', 501),
  ('01930000-0000-4000-8000-000000000502', 'agent:business:data-analysis:use',
   '使用数据分析', 'tenant', true, 'agent:business:data-analysis', 502),
  ('01930000-0000-4000-8000-000000000503', 'agent:business:intelligent-tracing:use',
   '使用智能溯源', 'tenant', true, 'agent:business:intelligent-tracing', 503)
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- 3. Agent 运营查看权限（非业务使用码；既有环境已登记时保持原 id/名称）
-- ===========================================================================

INSERT INTO iam.permissions (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort)
VALUES
  ('01930000-0000-4000-8000-000000000511', 'agent:operations:read',
   '查看企业运行明细', 'tenant', true, NULL, 511),
  ('01930000-0000-4000-8000-000000000512', 'agent:metrics:read',
   '查看运行统计', 'tenant', true, NULL, 512),
  ('01930000-0000-4000-8000-000000000513', 'agent:content:read',
   '读取问题原文', 'tenant', true, NULL, 513)
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- 4. 权限启停影响有效许可时推进受影响主体修订
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.bump_affected_on_permission_status() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;
    END IF;
    PERFORM set_config('app.is_platform', 'on', true);
    -- 平台角色持有者
    UPDATE iam.users SET auth_revision = auth_revision + 1
     WHERE id IN (
        SELECT ur.user_id FROM iam.user_roles ur
         WHERE ur.role_id IN (
            SELECT rp.role_id FROM iam.role_permissions rp
             WHERE rp.permission_id = NEW.id
               AND EXISTS (SELECT 1 FROM iam.roles r
                            WHERE r.id = rp.role_id AND r.scope = 'platform')));
    -- 企业角色持有成员
    UPDATE iam.tenant_memberships SET revision = revision + 1
     WHERE id IN (
        SELECT mr.membership_id FROM iam.membership_roles mr
         WHERE mr.role_id IN (
            SELECT rp.role_id FROM iam.role_permissions rp
             WHERE rp.permission_id = NEW.id));
    -- 企业上下文：资源型权限影响所有已开通该资源的企业，避免旧执行引用继续放行
    IF NEW.resource_code IS NOT NULL THEN
        UPDATE iam.tenants t SET auth_revision = auth_revision + 1
         WHERE t.id IN (
            SELECT te.tenant_id FROM iam.tenant_entitlements te
             WHERE te.resource_code = NEW.resource_code AND te.status = 'active'
            UNION
            SELECT r.tenant_id FROM iam.roles r
              JOIN iam.role_permissions rp ON rp.role_id = r.id
             WHERE rp.permission_id = NEW.id AND r.tenant_id IS NOT NULL);
    END IF;
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS permissions_bump_affected ON iam.permissions;
CREATE TRIGGER permissions_bump_affected
    AFTER UPDATE OF status ON iam.permissions
    FOR EACH ROW EXECUTE FUNCTION iam.bump_affected_on_permission_status();

REVOKE ALL ON FUNCTION iam.bump_affected_on_permission_status() FROM PUBLIC;
