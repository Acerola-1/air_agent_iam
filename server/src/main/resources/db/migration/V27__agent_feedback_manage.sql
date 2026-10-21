-- Change6：登记独立反馈处理权限；仅进入目录，不自动授予企业/角色/root。
SELECT set_config('app.is_platform', 'on', true);

INSERT INTO iam.permissions
    (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort)
VALUES
    ('01930000-0000-4000-8000-000000000514', 'agent:feedback:manage',
     '处理用户反馈', 'tenant', true, NULL, 514)
ON CONFLICT (code) DO NOTHING;
