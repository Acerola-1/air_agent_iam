package com.airagent.iam.admin.service;

import com.airagent.iam.admin.dto.CreateRoleDTO;
import com.airagent.iam.admin.dto.RolePermissionsDTO;
import com.airagent.iam.admin.dto.UpdateRoleDTO;
import com.airagent.iam.admin.vo.GrantableTreeVO;
import com.airagent.iam.admin.vo.PermissionVO;
import com.airagent.iam.admin.vo.RoleVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import java.util.List;

/** 角色、权限目录及可授权限业务接口。 */
public interface RoleAdminService {
    PageVO<RoleVO> listRoles(CurrentSession actor, String scope, Integer limit, String cursor);
    RoleVO createRole(CurrentSession actor, CreateRoleDTO request);
    RoleVO updateRole(CurrentSession actor, String roleId, UpdateRoleDTO request);
    RoleVO replacePermissions(CurrentSession actor, String roleId, RolePermissionsDTO request);
    List<PermissionVO> listPermissions(CurrentSession actor);
    GrantableTreeVO grantableTree(CurrentSession actor);
}
