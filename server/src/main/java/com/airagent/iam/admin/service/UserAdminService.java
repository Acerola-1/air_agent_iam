package com.airagent.iam.admin.service;

import com.airagent.iam.admin.dto.CreateUserDTO;
import com.airagent.iam.admin.dto.PlatformRolesDTO;
import com.airagent.iam.admin.dto.ResetPasswordDTO;
import com.airagent.iam.admin.dto.UpdateUserDTO;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/** 平台账号生命周期及角色分配业务。 */
public interface UserAdminService {
    PageVO<UserVO> list(CurrentSession actor, Integer limit, String cursor, String query);
    UserVO get(CurrentSession actor, String userId);
    UserVO create(CurrentSession actor, CreateUserDTO request);
    UserVO update(CurrentSession actor, String userId, UpdateUserDTO request);
    void resetPassword(CurrentSession actor, String userId, ResetPasswordDTO request);
    UserVO replacePlatformRoles(CurrentSession actor, String userId, PlatformRolesDTO request);
}
