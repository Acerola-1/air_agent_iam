-- Change7：登记需求洞察管理权限；仅进入目录，不自动授予企业/角色/root。
SELECT set_config('app.is_platform', 'on', true);

INSERT INTO iam.permissions
    (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort)
VALUES
    ('01930000-0000-4000-8000-000000000515', 'agent:insights:manage',
     '运营需求洞察', 'tenant', true, NULL, 515)
ON CONFLICT (code) DO NOTHING;
