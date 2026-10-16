-- IAM I1 身份域初始结构（schema: iam / iam_auth）
-- 运行角色：iam_migrate（schema 属主）；请求角色：iam_app（非 owner、NOBYPASSRLS）。

-- ===========================================================================
-- 账号与企业组织
-- ===========================================================================

CREATE TABLE iam.users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm           text NOT NULL DEFAULT 'workforce',
    account         text NOT NULL,
    display_name    text NOT NULL,
    password_hash   text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    auth_revision   bigint NOT NULL DEFAULT 0 CHECK (auth_revision >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_realm_account_uk UNIQUE (realm, account),
    CONSTRAINT users_account_ascii_ck CHECK (account ~ '^[[:graph:]]{3,64}$')
);

CREATE TABLE iam.tenants (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code            text NOT NULL,
    name            text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    auth_revision   bigint NOT NULL DEFAULT 1 CHECK (auth_revision >= 1),
    created_by      uuid REFERENCES iam.users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenants_code_uk UNIQUE (code)
);

CREATE TABLE iam.departments (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES iam.tenants(id),
    parent_id       uuid,
    code            text NOT NULL,
    name            text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT departments_tenant_code_uk UNIQUE (tenant_id, code),
    CONSTRAINT departments_tenant_id_id_uk UNIQUE (tenant_id, id)
);

ALTER TABLE iam.departments
    ADD CONSTRAINT departments_parent_same_tenant_fk
    FOREIGN KEY (tenant_id, parent_id) REFERENCES iam.departments(tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE TABLE iam.tenant_memberships (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES iam.tenants(id),
    user_id         uuid NOT NULL REFERENCES iam.users(id),
    department_id   uuid,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    revision        bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by      uuid REFERENCES iam.users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT memberships_tenant_user_uk UNIQUE (tenant_id, user_id),
    CONSTRAINT memberships_tenant_id_id_uk UNIQUE (tenant_id, id)
);

ALTER TABLE iam.tenant_memberships
    ADD CONSTRAINT memberships_department_same_tenant_fk
    FOREIGN KEY (tenant_id, department_id) REFERENCES iam.departments(tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE INDEX idx_memberships_user ON iam.tenant_memberships(user_id);

-- ===========================================================================
-- 角色、权限与授权关系
-- ===========================================================================

CREATE TABLE iam.roles (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code            text NOT NULL,
    scope           text NOT NULL CHECK (scope IN ('platform','tenant')),
    tenant_id       uuid REFERENCES iam.tenants(id),
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    is_builtin      boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_tenant_id_id_uk UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX roles_platform_code_uk ON iam.roles(code) WHERE scope = 'platform';
CREATE UNIQUE INDEX roles_tenant_code_uk ON iam.roles(tenant_id, code) WHERE scope = 'tenant';

CREATE TABLE iam.permissions (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code                    text NOT NULL UNIQUE,
    name_zh                 text NOT NULL,
    scope                   text NOT NULL CHECK (scope IN ('platform','tenant')),
    grantable_to_tenants    boolean NOT NULL DEFAULT false,
    resource_code           text,
    status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    sort                    integer NOT NULL DEFAULT 0,
    created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.role_permissions (
    role_id         uuid NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    permission_id   uuid NOT NULL REFERENCES iam.permissions(id),
    granted_by      uuid REFERENCES iam.users(id),
    granted_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT role_permissions_pk PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX idx_role_permissions_permission ON iam.role_permissions(permission_id);

CREATE TABLE iam.user_roles (
    user_id         uuid NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    role_id         uuid NOT NULL REFERENCES iam.roles(id),
    granted_by      uuid REFERENCES iam.users(id),
    granted_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_roles_pk PRIMARY KEY (user_id, role_id)
);

CREATE TABLE iam.membership_roles (
    tenant_id       uuid NOT NULL,
    membership_id   uuid NOT NULL,
    role_id         uuid NOT NULL REFERENCES iam.roles(id),
    granted_by      uuid REFERENCES iam.users(id),
    granted_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT membership_roles_pk PRIMARY KEY (membership_id, role_id)
);
-- 内置企业角色为全局模板（roles.tenant_id IS NULL）；租户自定义角色必须同租户。
-- 同租户约束由 guard_role_assignment_boundary 触发器保证（见下文）。
ALTER TABLE iam.membership_roles
    ADD CONSTRAINT membership_roles_membership_fk
    FOREIGN KEY (tenant_id, membership_id) REFERENCES iam.tenant_memberships(tenant_id, id) ON DELETE CASCADE;
CREATE INDEX idx_membership_roles_role ON iam.membership_roles(role_id);

-- ===========================================================================
-- 人类会话（PG 权威）
-- ===========================================================================

CREATE TABLE iam.auth_sessions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid NOT NULL REFERENCES iam.users(id),
    realm               text NOT NULL DEFAULT 'workforce',
    login_audience      text NOT NULL,
    token_digest        text NOT NULL UNIQUE,
    current_tenant_id   uuid REFERENCES iam.tenants(id),
    ctx_version         bigint NOT NULL DEFAULT 1 CHECK (ctx_version >= 1),
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    idle_expires_at     timestamptz,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoke_reason       text
);
CREATE INDEX idx_auth_sessions_user ON iam.auth_sessions(user_id);

-- ===========================================================================
-- 审计与撤销 outbox（授权修改与审计同事务；Redis 清理可重放）
-- ===========================================================================

CREATE TABLE iam.audit_logs (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       uuid,
    actor_user_id   uuid,
    actor_type      text NOT NULL CHECK (actor_type IN ('human','service_account','internal_client','bootstrap','anonymous')),
    action          text NOT NULL,
    target_type     text NOT NULL,
    target_id       text,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_id      text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_tenant_id_id ON iam.audit_logs(tenant_id, id DESC);
CREATE INDEX idx_audit_created_at ON iam.audit_logs(created_at DESC);

CREATE TABLE iam.outbox (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('redis_delete_keys','redis_delete_pattern')),
    payload     jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','dead')),
    attempts    integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_outbox_claim ON iam.outbox(status, available_at) WHERE status = 'pending';

-- ===========================================================================
-- 内部客户端、服务账号与执行上下文引用
-- ===========================================================================

CREATE TABLE iam.internal_clients (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       text NOT NULL UNIQUE,
    name            text NOT NULL,
    secret_digest   text NOT NULL,
    scopes          text[] NOT NULL DEFAULT '{}',
    audiences       text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','revoked')),
    revision        bigint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz
);

CREATE TABLE iam.service_accounts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account         text NOT NULL UNIQUE,
    name            text NOT NULL,
    tenant_id       uuid NOT NULL REFERENCES iam.tenants(id),
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','revoked')),
    audiences       text[] NOT NULL DEFAULT '{}',
    expires_at      timestamptz NOT NULL,
    revision        bigint NOT NULL DEFAULT 1,
    created_by      uuid REFERENCES iam.users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    CONSTRAINT service_accounts_expiry_ck CHECK (expires_at <= now() + interval '365 days'),
    CONSTRAINT service_accounts_tenant_id_id_uk UNIQUE (tenant_id, id)
);

CREATE TABLE iam.service_account_permissions (
    tenant_id           uuid NOT NULL,
    service_account_id  uuid NOT NULL,
    permission_id       uuid NOT NULL REFERENCES iam.permissions(id),
    granted_by          uuid REFERENCES iam.users(id),
    granted_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_account_permissions_pk PRIMARY KEY (service_account_id, permission_id)
);
ALTER TABLE iam.service_account_permissions
    ADD CONSTRAINT service_account_permissions_sa_fk
    FOREIGN KEY (tenant_id, service_account_id) REFERENCES iam.service_accounts(tenant_id, id) ON DELETE CASCADE;

CREATE TABLE iam.service_tokens (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id  uuid NOT NULL REFERENCES iam.service_accounts(id) ON DELETE CASCADE,
    credential_id       text NOT NULL UNIQUE,
    token_digest        text NOT NULL UNIQUE,
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    overlap_until       timestamptz,
    revoked_at          timestamptz
);
CREATE INDEX idx_service_tokens_account ON iam.service_tokens(service_account_id);

CREATE TABLE iam.verification_refs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       text NOT NULL,
    audience        text NOT NULL,
    session_id      uuid NOT NULL REFERENCES iam.auth_sessions(id),
    user_id         uuid NOT NULL,
    tenant_id       uuid,
    revisions       jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz NOT NULL,
    last_checked_at timestamptz
);
CREATE INDEX idx_verification_refs_session ON iam.verification_refs(session_id);

-- ===========================================================================
-- 浏览器会话句柄与 SSO（合成自有客户端）
-- ===========================================================================

CREATE TABLE iam.browser_handles (
    handle_digest       text PRIMARY KEY,
    session_id          uuid REFERENCES iam.auth_sessions(id),
    csrf_token          text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    authenticated_at    timestamptz,
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz
);

CREATE TABLE iam.sso_clients (
    client_id       text PRIMARY KEY,
    name            text NOT NULL,
    secret_digest   text NOT NULL,
    callback_url    text NOT NULL,
    origins         text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.sso_states (
    state_digest    text PRIMARY KEY,
    client_id       text NOT NULL REFERENCES iam.sso_clients(client_id),
    handle_digest   text NOT NULL,
    redirect_uri    text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz
);

CREATE TABLE iam.sso_tickets (
    ticket_digest   text PRIMARY KEY,
    client_id       text NOT NULL REFERENCES iam.sso_clients(client_id),
    session_id      uuid NOT NULL REFERENCES iam.auth_sessions(id),
    redirect_uri    text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz
);

-- ===========================================================================
-- 资源目录与企业开通（契约随 I1 冻结；开通能力在 I1a 实现）
-- ===========================================================================

CREATE TABLE iam.resource_catalog (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code            text NOT NULL UNIQUE,
    name_zh         text NOT NULL,
    sort            integer NOT NULL DEFAULT 0,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    kind            text NOT NULL DEFAULT 'leaf',
    parent_code     text,
    revision        bigint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.tenant_entitlements (
    tenant_id       uuid NOT NULL REFERENCES iam.tenants(id),
    resource_code   text NOT NULL REFERENCES iam.resource_catalog(code),
    status          text NOT NULL DEFAULT 'revoked' CHECK (status IN ('active','revoked')),
    revision        bigint NOT NULL DEFAULT 1,
    granted_at      timestamptz,
    revoked_at      timestamptz,
    updated_by      uuid REFERENCES iam.users(id),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_entitlements_pk PRIMARY KEY (tenant_id, resource_code)
);

CREATE TABLE iam.bootstrap_meta (
    key         text PRIMARY KEY,
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ===========================================================================
-- updated_at 维护
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users','tenants','departments','tenant_memberships','roles','auth_sessions',
        'service_accounts','tenant_entitlements','outbox']
    LOOP
        EXECUTE format($f$CREATE TRIGGER %I_touch BEFORE UPDATE ON iam.%I
                       FOR EACH ROW EXECUTE FUNCTION iam.set_updated_at()$f$, t, t);
    END LOOP;
END;
$$;

-- ===========================================================================
-- 跨租户 / 可授边界触发器
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.guard_role_assignment_boundary() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_scope text; v_grantable boolean; v_resource text; v_tenant uuid;
BEGIN
    IF TG_TABLE_NAME = 'user_roles' THEN
        SELECT scope INTO v_scope FROM iam.roles WHERE id = NEW.role_id;
        IF v_scope IS DISTINCT FROM 'platform' THEN
            RAISE EXCEPTION '仅平台角色可分配到用户' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'membership_roles' THEN
        SELECT scope, tenant_id INTO v_scope, v_tenant FROM iam.roles WHERE id = NEW.role_id;
        IF v_scope IS DISTINCT FROM 'tenant' THEN
            RAISE EXCEPTION '企业成员仅可分配企业角色' USING ERRCODE = 'check_violation';
        END IF;
        IF v_tenant IS NOT NULL AND v_tenant IS DISTINCT FROM NEW.tenant_id THEN
            RAISE EXCEPTION '企业角色不属于该企业' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    SELECT r.scope, p.grantable_to_tenants, p.resource_code
      INTO v_scope, v_grantable, v_resource
      FROM iam.roles r JOIN iam.permissions p ON p.id = NEW.permission_id
     WHERE r.id = NEW.role_id;

    IF v_scope = 'tenant' AND NOT v_grantable THEN
        RAISE EXCEPTION '企业角色不可分配平台专属权限' USING ERRCODE = 'check_violation';
    END IF;
    IF v_resource IS NOT NULL THEN
        RAISE EXCEPTION '资源型权限在资源开通（I1a）前不可授予' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_roles_boundary BEFORE INSERT OR UPDATE ON iam.user_roles
    FOR EACH ROW EXECUTE FUNCTION iam.guard_role_assignment_boundary();
CREATE TRIGGER membership_roles_boundary BEFORE INSERT OR UPDATE ON iam.membership_roles
    FOR EACH ROW EXECUTE FUNCTION iam.guard_role_assignment_boundary();
CREATE TRIGGER role_permissions_boundary BEFORE INSERT OR UPDATE ON iam.role_permissions
    FOR EACH ROW EXECUTE FUNCTION iam.guard_role_assignment_boundary();

CREATE OR REPLACE FUNCTION iam.guard_service_permission_boundary() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_resource text;
BEGIN
    SELECT resource_code INTO v_resource FROM iam.permissions WHERE id = NEW.permission_id;
    IF v_resource IS NOT NULL THEN
        RAISE EXCEPTION '服务账号资源型权限在资源开通（I1a）前不可授予' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER service_permissions_boundary BEFORE INSERT OR UPDATE ON iam.service_account_permissions
    FOR EACH ROW EXECUTE FUNCTION iam.guard_service_permission_boundary();

-- ===========================================================================
-- 部门无环
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.reject_department_cycle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE hits integer;
BEGIN
    IF NEW.parent_id IS NULL THEN RETURN NEW; END IF;
    WITH RECURSIVE walk(depth, id, parent_id) AS (
        SELECT 1, id, parent_id FROM iam.departments
         WHERE tenant_id = NEW.tenant_id AND id = NEW.parent_id
        UNION ALL
        SELECT w.depth + 1, d.id, d.parent_id
          FROM iam.departments d JOIN walk w ON d.tenant_id = NEW.tenant_id AND d.id = w.parent_id
         WHERE w.depth < 100
    )
    SELECT count(*) INTO hits FROM walk WHERE id = NEW.id;
    IF hits > 0 OR NEW.parent_id = NEW.id THEN
        RAISE EXCEPTION '部门层级不允许成环' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER departments_no_cycle BEFORE INSERT OR UPDATE OF parent_id ON iam.departments
    FOR EACH ROW EXECUTE FUNCTION iam.reject_department_cycle();

-- ===========================================================================
-- 最后有效管理员保护（企业 tenant_admin / 平台 platform_super_admin）
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.guard_last_admin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_tenant uuid; v_count integer; v_user uuid;
BEGIN
    IF TG_TABLE_NAME = 'tenant_memberships' THEN
        v_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
        PERFORM 1 FROM iam.tenants WHERE id = v_tenant FOR UPDATE;
        SELECT count(DISTINCT m.id) INTO v_count
          FROM iam.tenant_memberships m
          JOIN iam.membership_roles mr ON mr.membership_id = m.id
          JOIN iam.roles r ON r.id = mr.role_id AND r.scope = 'tenant'
         WHERE m.tenant_id = v_tenant AND m.status = 'active' AND r.code = 'tenant_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '企业必须保留至少一个有效管理员' USING ERRCODE = 'check_violation';
        END IF;
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_TABLE_NAME = 'membership_roles' THEN
        v_tenant := OLD.tenant_id;
        PERFORM 1 FROM iam.tenants WHERE id = v_tenant FOR UPDATE;
        SELECT count(DISTINCT m.id) INTO v_count
          FROM iam.tenant_memberships m
          JOIN iam.membership_roles mr2 ON mr2.membership_id = m.id
          JOIN iam.roles r ON r.id = mr2.role_id AND r.scope = 'tenant'
         WHERE m.tenant_id = v_tenant AND m.status = 'active' AND r.code = 'tenant_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '企业必须保留至少一个有效管理员' USING ERRCODE = 'check_violation';
        END IF;
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_TABLE_NAME = 'user_roles' THEN
        v_user := COALESCE(NEW.user_id, OLD.user_id);
        PERFORM 1 FROM iam.users WHERE id = v_user FOR UPDATE;
        SELECT count(DISTINCT ur.user_id) INTO v_count
          FROM iam.user_roles ur
          JOIN iam.roles r ON r.id = ur.role_id AND r.scope = 'platform'
          JOIN iam.users u ON u.id = ur.user_id AND u.status = 'active'
         WHERE r.code = 'platform_super_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '平台必须保留至少一个有效超级管理员' USING ERRCODE = 'check_violation';
        END IF;
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_TABLE_NAME = 'users' THEN
        SELECT count(DISTINCT ur.user_id) INTO v_count
          FROM iam.user_roles ur
          JOIN iam.roles r ON r.id = ur.role_id AND r.scope = 'platform'
          JOIN iam.users u ON u.id = ur.user_id AND u.status = 'active'
         WHERE r.code = 'platform_super_admin';
        IF v_count = 0 THEN
            RAISE EXCEPTION '平台必须保留至少一个有效超级管理员' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER memberships_last_admin AFTER UPDATE OF status OR DELETE ON iam.tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION iam.guard_last_admin();
CREATE TRIGGER membership_roles_last_admin_delete AFTER DELETE ON iam.membership_roles
    FOR EACH ROW EXECUTE FUNCTION iam.guard_last_admin();
CREATE TRIGGER membership_roles_last_admin_update AFTER UPDATE OF role_id ON iam.membership_roles
    FOR EACH ROW WHEN (OLD.role_id IS DISTINCT FROM NEW.role_id)
    EXECUTE FUNCTION iam.guard_last_admin();
CREATE TRIGGER user_roles_last_admin AFTER DELETE ON iam.user_roles
    FOR EACH ROW EXECUTE FUNCTION iam.guard_last_admin();
CREATE TRIGGER users_last_admin AFTER UPDATE OF status ON iam.users
    FOR EACH ROW EXECUTE FUNCTION iam.guard_last_admin();

-- ===========================================================================
-- 授权
-- ===========================================================================

GRANT USAGE ON SCHEMA iam, iam_auth TO iam_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam TO iam_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA iam TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam
    GRANT USAGE, SELECT ON SEQUENCES TO iam_app;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrate IN SCHEMA iam, iam_auth
    GRANT EXECUTE ON FUNCTIONS TO iam_app;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;

-- ===========================================================================
-- 行级安全
-- FORCE：租户数据表（含 owner 经函数访问仍按策略过滤）
-- ENABLE：身份/会话/目录表，iam_app 按策略访问；iam_auth 属主函数作为受控引导网关
-- 无策略 ENABLE：机器主体/票据/句柄表，对 iam_app 全拒绝，仅 iam_auth 函数可访问
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.ctx_uuid(name text) RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting(name, true), '')::uuid $$;

CREATE OR REPLACE FUNCTION iam.ctx_platform() RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT coalesce(nullif(current_setting('app.is_platform', true), ''), 'off') = 'on' $$;

ALTER TABLE iam.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_tenant ON iam.tenants
    USING (id = iam.ctx_uuid('app.tenant_id')
           OR iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                       WHERE m.tenant_id = tenants.id AND m.user_id = iam.ctx_uuid('app.user_id')
                         AND m.status = 'active'))
    WITH CHECK (iam.ctx_platform());

ALTER TABLE iam.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.departments FORCE ROW LEVEL SECURITY;
CREATE POLICY departments_tenant ON iam.departments
    USING (tenant_id = iam.ctx_uuid('app.tenant_id')
           OR iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                       WHERE m.tenant_id = departments.tenant_id AND m.user_id = iam.ctx_uuid('app.user_id')
                         AND m.status = 'active'))
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

ALTER TABLE iam.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenant_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_tenant ON iam.tenant_memberships
    USING (tenant_id = iam.ctx_uuid('app.tenant_id')
           OR user_id = iam.ctx_uuid('app.user_id')
           OR iam.ctx_platform())
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id')
                OR user_id = iam.ctx_uuid('app.user_id')
                OR iam.ctx_platform());

ALTER TABLE iam.membership_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.membership_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY membership_roles_tenant ON iam.membership_roles
    USING (tenant_id = iam.ctx_uuid('app.tenant_id')
           OR iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                       WHERE m.id = membership_roles.membership_id
                         AND m.user_id = iam.ctx_uuid('app.user_id')))
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

ALTER TABLE iam.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_tenant ON iam.audit_logs
    USING ((tenant_id IS NOT NULL AND tenant_id = iam.ctx_uuid('app.tenant_id')) OR iam.ctx_platform())
    WITH CHECK ((tenant_id IS NOT NULL AND tenant_id = iam.ctx_uuid('app.tenant_id')) OR iam.ctx_platform());

ALTER TABLE iam.service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.service_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY service_accounts_tenant ON iam.service_accounts
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform())
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

ALTER TABLE iam.service_account_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.service_account_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY service_account_permissions_tenant ON iam.service_account_permissions
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform())
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

ALTER TABLE iam.tenant_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenant_entitlements FORCE ROW LEVEL SECURITY;
CREATE POLICY entitlements_tenant ON iam.tenant_entitlements
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform())
    WITH CHECK (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform());

ALTER TABLE iam.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_policy ON iam.users
    USING (id = iam.ctx_uuid('app.user_id')
           OR iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                       WHERE m.user_id = users.id AND m.tenant_id = iam.ctx_uuid('app.tenant_id')
                         AND m.status = 'active'))
    WITH CHECK (id = iam.ctx_uuid('app.user_id') OR iam.ctx_platform());

ALTER TABLE iam.user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_roles_policy ON iam.user_roles
    USING (user_id = iam.ctx_uuid('app.user_id') OR iam.ctx_platform())
    WITH CHECK (iam.ctx_platform());

ALTER TABLE iam.auth_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth_sessions_policy ON iam.auth_sessions
    USING (user_id = iam.ctx_uuid('app.user_id') OR iam.ctx_platform())
    WITH CHECK (user_id = iam.ctx_uuid('app.user_id') OR iam.ctx_platform());

ALTER TABLE iam.roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY roles_policy ON iam.roles
    USING (tenant_id IS NULL
           OR tenant_id = iam.ctx_uuid('app.tenant_id')
           OR iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                       WHERE m.tenant_id = roles.tenant_id AND m.user_id = iam.ctx_uuid('app.user_id')
                         AND m.status = 'active'))
    WITH CHECK ((scope = 'tenant' AND tenant_id = iam.ctx_uuid('app.tenant_id'))
                OR (scope = 'platform' AND iam.ctx_platform() AND tenant_id IS NULL));

ALTER TABLE iam.role_permissions ENABLE ROW LEVEL SECURITY;
CREATE POLICY role_permissions_policy ON iam.role_permissions
    USING (iam.ctx_platform()
           OR EXISTS (SELECT 1 FROM iam.roles r
                       WHERE r.id = role_permissions.role_id
                         AND (r.tenant_id = iam.ctx_uuid('app.tenant_id') OR r.tenant_id IS NULL
                              OR EXISTS (SELECT 1 FROM iam.tenant_memberships m
                                          WHERE m.tenant_id = r.tenant_id
                                            AND m.user_id = iam.ctx_uuid('app.user_id')
                                            AND m.status = 'active'))))
    WITH CHECK (EXISTS (SELECT 1 FROM iam.roles r
                         WHERE r.id = role_permissions.role_id
                           AND ((r.scope = 'tenant' AND r.tenant_id = iam.ctx_uuid('app.tenant_id'))
                                OR (r.scope = 'platform' AND iam.ctx_platform()))));

ALTER TABLE iam.internal_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.service_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.verification_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.browser_handles ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sso_tickets ENABLE ROW LEVEL SECURITY;

-- ===========================================================================
-- iam_auth：事务内可信上下文与预授权引导查询
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam_auth.set_request_context(p_user uuid, p_tenant uuid, p_platform boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    PERFORM set_config('app.user_id', coalesce(p_user::text, ''), true);
    PERFORM set_config('app.tenant_id', coalesce(p_tenant::text, ''), true);
    PERFORM set_config('app.is_platform', CASE WHEN p_platform THEN 'on' ELSE 'off' END, true);
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.find_user_for_login(p_realm text, p_account text)
RETURNS SETOF iam.users LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY SELECT u.* FROM iam.users u WHERE u.realm = p_realm AND u.account = p_account;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.find_session_by_digest(p_digest text)
RETURNS SETOF iam.auth_sessions LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY SELECT s.* FROM iam.auth_sessions s WHERE s.token_digest = p_digest;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.enqueue_outbox(p_kind text, p_payload jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
    INSERT INTO iam.outbox(kind, payload) VALUES (p_kind, p_payload) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.claim_due_outbox(p_limit integer DEFAULT 16)
RETURNS SETOF iam.outbox LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
      WITH picked AS (
        SELECT id FROM iam.outbox
         WHERE status = 'pending' AND available_at <= now()
         ORDER BY id LIMIT p_limit
         FOR UPDATE SKIP LOCKED
      )
      UPDATE iam.outbox o SET attempts = o.attempts + 1, updated_at = now()
        FROM picked WHERE o.id = picked.id
        RETURNING o.*;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.complete_outbox(p_id bigint, p_dead boolean DEFAULT false)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.outbox
       SET status = CASE WHEN p_dead THEN 'dead' ELSE 'done' END,
           available_at = CASE WHEN p_dead THEN now() ELSE available_at END,
           updated_at = now()
     WHERE id = p_id;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.requeue_outbox(p_id bigint, p_attempts integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.outbox
       SET status = CASE WHEN attempts >= p_attempts THEN 'dead' ELSE 'pending' END,
           available_at = now() + least(interval '30 seconds', interval '1 second' * pow(2, least(attempts, 4))),
           updated_at = now()
     WHERE id = p_id;
END;
$$;

REVOKE ALL ON FUNCTION iam.ctx_uuid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.ctx_platform() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.ctx_uuid(text) TO iam_app;
GRANT EXECUTE ON FUNCTION iam.ctx_platform() TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.set_request_context(uuid, uuid, boolean) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.find_user_for_login(text, text) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.find_session_by_digest(text) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.enqueue_outbox(text, jsonb) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.claim_due_outbox(integer) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.complete_outbox(bigint, boolean) TO iam_app;
GRANT EXECUTE ON FUNCTION iam_auth.requeue_outbox(bigint, integer) TO iam_app;
