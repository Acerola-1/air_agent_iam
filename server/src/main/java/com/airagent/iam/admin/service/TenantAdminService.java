package com.airagent.iam.admin.service;

import com.airagent.iam.admin.dto.CreateDepartmentDTO;
import com.airagent.iam.admin.dto.CreateMembershipDTO;
import com.airagent.iam.admin.dto.CreateTenantDTO;
import com.airagent.iam.admin.dto.MemberRolesDTO;
import com.airagent.iam.admin.dto.UpdateDepartmentDTO;
import com.airagent.iam.admin.dto.UpdateMembershipDTO;
import com.airagent.iam.admin.dto.UpdateTenantDTO;
import com.airagent.iam.admin.vo.DepartmentVO;
import com.airagent.iam.admin.vo.MemberVO;
import com.airagent.iam.admin.vo.TenantVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/** 企业、成员及部门业务接口。 */
public interface TenantAdminService {
    PageVO<TenantVO> listTenants(CurrentSession actor, Integer limitRaw, String cursorRaw);
    TenantVO getTenant(CurrentSession actor, String tenantIdRaw);
    TenantVO createTenant(CurrentSession actor, CreateTenantDTO req);
    TenantVO updateTenant(CurrentSession actor, String tenantId, UpdateTenantDTO req);
    PageVO<MemberVO> listMembers(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);
    MemberVO createMembership(CurrentSession actor, CreateMembershipDTO req);
    MemberVO updateMembership(CurrentSession actor, String membershipIdRaw, UpdateMembershipDTO req);
    void deleteMembership(CurrentSession actor, String membershipIdRaw);
    MemberVO replaceMemberRoles(CurrentSession actor, String membershipIdRaw, MemberRolesDTO req);
    PageVO<DepartmentVO> listDepartments(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);
    DepartmentVO createDepartment(CurrentSession actor, String tenantIdRaw, CreateDepartmentDTO req);
    DepartmentVO updateDepartment(CurrentSession actor, String departmentIdRaw, UpdateDepartmentDTO req);
}
