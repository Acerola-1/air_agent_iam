-- 协调者补修：已执行V20/V21保持不变，企业开通只读与目录修订扇出用增量迁移修正。
DROP POLICY IF EXISTS entitlements_tenant ON iam.tenant_entitlements;
CREATE POLICY entitlements_read ON iam.tenant_entitlements FOR SELECT
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());
CREATE POLICY entitlements_insert ON iam.tenant_entitlements FOR INSERT WITH CHECK (iam.ctx_platform());
CREATE POLICY entitlements_update ON iam.tenant_entitlements FOR UPDATE
    USING (iam.ctx_platform()) WITH CHECK (iam.ctx_platform());
CREATE POLICY entitlements_delete ON iam.tenant_entitlements FOR DELETE USING (iam.ctx_platform());

CREATE OR REPLACE FUNCTION iam.bump_tenants_on_resource_status() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_platform text := current_setting('app.is_platform', true);
    v_tenant uuid;
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
    PERFORM set_config('app.is_platform', 'on', true);
    FOR v_tenant IN
        SELECT t.id FROM iam.tenants t WHERE t.id IN (
            SELECT te.tenant_id FROM iam.tenant_entitlements te
             WHERE te.resource_code=NEW.code AND te.status='active'
            UNION
            SELECT r.tenant_id FROM iam.roles r
              JOIN iam.role_permissions rp ON rp.role_id=r.id
              JOIN iam.permissions p ON p.id=rp.permission_id
             WHERE p.resource_code=NEW.code AND r.tenant_id IS NOT NULL
            UNION
            SELECT sa.tenant_id FROM iam.service_accounts sa
              JOIN iam.service_account_permissions sap ON sap.service_account_id=sa.id
              JOIN iam.permissions p ON p.id=sap.permission_id
             WHERE p.resource_code=NEW.code
        ) ORDER BY t.id FOR UPDATE OF t
    LOOP
        UPDATE iam.tenants SET auth_revision=auth_revision+1 WHERE id=v_tenant;
    END LOOP;
    PERFORM set_config('app.is_platform',COALESCE(v_platform,'off'),true);
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION iam.bump_tenants_on_resource_status() FROM PUBLIC;
