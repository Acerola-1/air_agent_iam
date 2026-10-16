-- 组织明细只在当前企业上下文内可见；跨企业成员资格不扩展部门读权限。
ALTER POLICY departments_tenant ON iam.departments
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform())
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

-- 普通管理查询不能直接读写口令摘要；口令核验/修改只能经过 iam_auth 网关。
REVOKE SELECT, UPDATE ON iam.users FROM iam_app;
GRANT SELECT (id, realm, account, display_name, status, auth_revision, created_at, updated_at)
    ON iam.users TO iam_app;
GRANT UPDATE (display_name, status, auth_revision, updated_at) ON iam.users TO iam_app;

-- 平台与企业管理员保护使用同一个事务锁，覆盖跨用户并发停用和跨表撤权。
CREATE OR REPLACE FUNCTION iam.guard_last_admin() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_tenant uuid;
    v_count bigint;
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    PERFORM pg_advisory_xact_lock(169721, 1);
    PERFORM set_config('app.is_platform', 'on', true);

    IF TG_TABLE_NAME = 'users' THEN
        IF NEW.status = 'active' THEN
            PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
            RETURN NEW;
        END IF;
        IF EXISTS (SELECT 1 FROM iam.user_roles ur JOIN iam.roles r ON r.id = ur.role_id
                    WHERE ur.user_id = NEW.id AND r.code = 'platform_super_admin' AND r.scope = 'platform') THEN
            SELECT count(DISTINCT u.id) INTO v_count
              FROM iam.users u JOIN iam.user_roles ur ON ur.user_id = u.id
              JOIN iam.roles r ON r.id = ur.role_id
             WHERE u.status = 'active' AND r.status = 'active'
               AND r.scope = 'platform' AND r.code = 'platform_super_admin';
            IF v_count = 0 THEN
                RAISE EXCEPTION '平台必须保留至少一个有效超级管理员' USING ERRCODE = '23514';
            END IF;
        END IF;
        FOR v_tenant IN
            SELECT DISTINCT m.tenant_id FROM iam.tenant_memberships m
            JOIN iam.membership_roles mr ON mr.membership_id = m.id
            JOIN iam.roles r ON r.id = mr.role_id
            WHERE m.user_id = NEW.id AND m.status = 'active' AND r.code = 'tenant_admin'
        LOOP
            SELECT count(DISTINCT m.id) INTO v_count
              FROM iam.tenant_memberships m JOIN iam.users u ON u.id = m.user_id
              JOIN iam.membership_roles mr ON mr.membership_id = m.id JOIN iam.roles r ON r.id = mr.role_id
             WHERE m.tenant_id = v_tenant AND m.status = 'active' AND u.status = 'active'
               AND r.status = 'active' AND r.scope = 'tenant' AND r.code = 'tenant_admin';
            IF v_count = 0 THEN
                RAISE EXCEPTION '企业必须保留至少一个有效管理员' USING ERRCODE = '23514';
            END IF;
        END LOOP;
    ELSIF TG_TABLE_NAME = 'user_roles' THEN
        SELECT count(DISTINCT u.id) INTO v_count
          FROM iam.users u JOIN iam.user_roles ur ON ur.user_id = u.id JOIN iam.roles r ON r.id = ur.role_id
         WHERE u.status = 'active' AND r.status = 'active'
           AND r.scope = 'platform' AND r.code = 'platform_super_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '平台必须保留至少一个有效超级管理员' USING ERRCODE = '23514';
        END IF;
    ELSE
        v_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
        SELECT count(DISTINCT m.id) INTO v_count
          FROM iam.tenant_memberships m JOIN iam.users u ON u.id = m.user_id
          JOIN iam.membership_roles mr ON mr.membership_id = m.id JOIN iam.roles r ON r.id = mr.role_id
         WHERE m.tenant_id = v_tenant AND m.status = 'active' AND u.status = 'active'
           AND r.status = 'active' AND r.scope = 'tenant' AND r.code = 'tenant_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '企业必须保留至少一个有效管理员' USING ERRCODE = '23514';
        END IF;
    END IF;
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN COALESCE(NEW, OLD);
END;
$$;
