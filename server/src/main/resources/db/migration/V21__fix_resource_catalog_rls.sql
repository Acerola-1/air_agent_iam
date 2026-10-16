-- V21: 修复 resource_catalog RLS UPDATE 策略
-- 根因：FOR ALL WITH CHECK 的 USING 默认等于 WITH CHECK，导致 UPDATE 被拦截。
--       必须显式分离 USING 与 WITH CHECK。

ALTER TABLE iam.resource_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.resource_catalog FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS resource_catalog_read ON iam.resource_catalog;
DROP POLICY IF EXISTS resource_catalog_write ON iam.resource_catalog;
DROP POLICY IF EXISTS resource_catalog_select ON iam.resource_catalog;
DROP POLICY IF EXISTS resource_catalog_insert ON iam.resource_catalog;
DROP POLICY IF EXISTS resource_catalog_update ON iam.resource_catalog;
DROP POLICY IF EXISTS resource_catalog_delete ON iam.resource_catalog;

CREATE POLICY resource_catalog_select ON iam.resource_catalog
    FOR SELECT USING (iam.ctx_platform() OR iam.ctx_uuid('app.user_id') IS NOT NULL);

CREATE POLICY resource_catalog_insert ON iam.resource_catalog
    FOR INSERT WITH CHECK (iam.ctx_platform());

CREATE POLICY resource_catalog_update ON iam.resource_catalog
    FOR UPDATE
    USING (iam.ctx_platform() OR iam.ctx_uuid('app.user_id') IS NOT NULL)
    WITH CHECK (iam.ctx_platform());

CREATE POLICY resource_catalog_delete ON iam.resource_catalog
    FOR DELETE USING (iam.ctx_platform());
