-- 内置权限、内置角色与资源目录幂等种子（固定合成 UUID；重复执行不产生重复、不重置口令）。
-- knowledge:lib:air:read 仅冻结契约：I1 不分配给任何角色，授予在数据库触发器层面拒绝。

INSERT INTO iam.permissions (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort) VALUES
  ('01930000-0000-4000-8000-000000000001','platform:user:read','平台用户查看','platform',false,NULL,101),
  ('01930000-0000-4000-8000-000000000002','platform:user:write','平台用户建档与停用','platform',false,NULL,102),
  ('01930000-0000-4000-8000-000000000003','platform:user:password:reset','平台重置用户密码','platform',false,NULL,103),
  ('01930000-0000-4000-8000-000000000004','platform:user:role:assign','分配平台角色','platform',false,NULL,104),
  ('01930000-0000-4000-8000-000000000011','platform:tenant:read','平台企业查看','platform',false,NULL,111),
  ('01930000-0000-4000-8000-000000000012','platform:tenant:write','平台企业建档与状态','platform',false,NULL,112),
  ('01930000-0000-4000-8000-000000000021','platform:role:read','平台角色查看','platform',false,NULL,121),
  ('01930000-0000-4000-8000-000000000022','platform:role:write','平台角色与权限管理','platform',false,NULL,122),
  ('01930000-0000-4000-8000-000000000031','platform:audit:read','平台审计查看','platform',false,NULL,131),
  ('01930000-0000-4000-8000-000000000041','platform:service:write','服务主体管理','platform',false,NULL,141),
  ('01930000-0000-4000-8000-000000000042','platform:client:write','内部客户端管理','platform',false,NULL,142),
  ('01930000-0000-4000-8000-000000000051','entitlement:manage','资源开通管理','platform',false,NULL,151),
  ('01930000-0000-4000-8000-000000000101','tenant:member:read','企业成员查看','tenant',true,NULL,201),
  ('01930000-0000-4000-8000-000000000102','tenant:member:write','企业成员与状态管理','tenant',true,NULL,202),
  ('01930000-0000-4000-8000-000000000111','tenant:department:read','企业部门查看','tenant',true,NULL,211),
  ('01930000-0000-4000-8000-000000000112','tenant:department:write','企业部门管理','tenant',true,NULL,212),
  ('01930000-0000-4000-8000-000000000121','tenant:role:read','企业角色查看','tenant',true,NULL,221),
  ('01930000-0000-4000-8000-000000000122','tenant:role:write','企业角色管理','tenant',true,NULL,222),
  ('01930000-0000-4000-8000-000000000131','tenant:audit:read','企业审计查看','tenant',true,NULL,231),
  ('01930000-0000-4000-8000-000000000201','knowledge:lib:air:read','空气知识库读取','tenant',true,'knowledge:lib:air',301)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.roles (id, code, scope, tenant_id, name, description, is_builtin) VALUES
  ('01930000-0000-4000-8000-000000000301','platform_super_admin','platform',NULL,'平台超级管理员','全部平台管理权限',true),
  ('01930000-0000-4000-8000-000000000302','platform_auditor','platform',NULL,'平台审计员','平台只读与审计查看',true),
  ('01930000-0000-4000-8000-000000000311','tenant_admin','tenant',NULL,'企业管理员','企业成员、部门、角色与审计管理',true),
  ('01930000-0000-4000-8000-000000000312','tenant_reader','tenant',NULL,'企业查询成员','企业只读查看',true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM (VALUES
    ('platform_super_admin', 'platform:user:read'),
    ('platform_super_admin', 'platform:user:write'),
    ('platform_super_admin', 'platform:user:password:reset'),
    ('platform_super_admin', 'platform:user:role:assign'),
    ('platform_super_admin', 'platform:tenant:read'),
    ('platform_super_admin', 'platform:tenant:write'),
    ('platform_super_admin', 'platform:role:read'),
    ('platform_super_admin', 'platform:role:write'),
    ('platform_super_admin', 'platform:audit:read'),
    ('platform_super_admin', 'platform:service:write'),
    ('platform_super_admin', 'platform:client:write'),
    ('platform_super_admin', 'entitlement:manage'),
    ('platform_auditor', 'platform:audit:read'),
    ('platform_auditor', 'platform:user:read'),
    ('platform_auditor', 'platform:tenant:read'),
    ('platform_auditor', 'platform:role:read'),
    ('tenant_admin', 'tenant:member:read'),
    ('tenant_admin', 'tenant:member:write'),
    ('tenant_admin', 'tenant:department:read'),
    ('tenant_admin', 'tenant:department:write'),
    ('tenant_admin', 'tenant:role:read'),
    ('tenant_admin', 'tenant:role:write'),
    ('tenant_admin', 'tenant:audit:read'),
    ('tenant_reader', 'tenant:member:read'),
    ('tenant_reader', 'tenant:department:read'),
    ('tenant_reader', 'tenant:role:read'),
    ('tenant_reader', 'tenant:audit:read')
  ) AS v(role_code, permission_code)
  JOIN iam.roles r ON r.code = v.role_code AND r.scope = CASE WHEN v.role_code LIKE 'platform_%' THEN 'platform' ELSE 'tenant' END
  JOIN iam.permissions p ON p.code = v.permission_code
ON CONFLICT DO NOTHING;

INSERT INTO iam.resource_catalog (code, name_zh, sort, status, kind, parent_code) VALUES
  ('knowledge:lib:air','空气知识库',10,'active','leaf','knowledge')
ON CONFLICT (code) DO NOTHING;
