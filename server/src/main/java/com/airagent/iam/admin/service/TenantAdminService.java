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

/**
 * 企业建档与状态、企业内成员、部门树的业务接口（Service 层）。
 *
 * <p>所有方法以已通过 Redis 与 PostgreSQL 双重核验的 {@link CurrentSession} 为 actor，
 * 在实现内部逐一裁决权限、开启事务并设置请求上下文（RLS）。两条授权面在此共存：
 * 企业主体走 {@code platform:tenant:read|write}（平台上下文、企业为空），
 * 成员与部门走 {@code tenant:member:*} / {@code tenant:department:*} / {@code tenant:role:write}
 * （上下文必须是会话当前企业）。
 *
 * <p>租户隔离的硬规则是“只认会话当前企业”：请求参数或请求体里出现的 tenant_id 只能缺省或
 * 与会话当前企业一致，跨企业一律 403（成员/部门资源 id 跨企业则统一 404，不泄露存在性）；
 * 部门写接口额外要求 {@code expected_ctx_version} 与会话上下文版本一致，否则 409。
 * 同租户复合外键、层级无环、最后管理员保护与角色域边界全部由数据库触发器兜底，
 * 应用层只做明确的 4xx 翻译。写操作与审计在同一事务提交，审计失败整体回滚。
 *
 * <p>修订号语义按实体区分：企业用 {@code auth_revision}（仅状态变化时推进），
 * 成员用 {@code revision}（状态/部门变更、角色增删、以及所关联角色的变化都会推进），
 * 部门无修订列（改用会话上下文版本守卫）。失败统一抛
 * {@link com.airagent.iam.web.error.ApiException}，由全局处理器映射 HTTP 状态。
 *
 * @author Acerola
 */
public interface TenantAdminService {

    /**
     * keyset 分页列出 actor 可见的企业。
     *
     * <p>以平台上下文查询，故平台侧可见全部企业；本方法属于平台授权面。
     *
     * @param actor     当前会话快照；需 {@code platform:tenant:read}
     * @param limitRaw  单页条数，{@code null} 取默认 20，范围 1..200
     * @param cursorRaw 上一页游标（base64url 的末行企业 id），{@code null}/空白表示首页
     * @return 当前页数据与下一页游标（无更多时为 {@code null}）
     * @throws com.airagent.iam.web.error.ApiException 403 缺权限；400 limit/cursor 不合法
     */
    PageVO<TenantVO> listTenants(CurrentSession actor, Integer limitRaw, String cursorRaw);

    /**
     * 查询单个企业详情。
     *
     * <p>权限面二选一：具备 {@code platform:tenant:read} 时按平台上下文读取任意企业；
     * 否则须具备企业成员或部门读权限，此时只能读取会话当前企业（跨企业 403、未选企业 400）。
     *
     * @param actor       当前会话快照；见上述二选一要求
     * @param tenantIdRaw 目标企业 UUID 文本
     * @return 企业视图（不含建档人等内部列）
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID，或企业面调用者未选择企业上下文；
     *         403 缺查看权限或跨企业读取；404 企业不存在或对当前上下文不可见
     */
    TenantVO getTenant(CurrentSession actor, String tenantIdRaw);

    /**
     * 企业建档：创建企业并同时生成首位管理员的成员关系与内置企业管理角色。
     *
     * <p>建档、成员、授权与两条审计在同一事务内完成，任一失败整体回滚；
     * 上下文先切平台写企业行，再切到新企业写成员与角色，最后切回平台上下文写平台线审计。
     *
     * @param actor 当前会话快照；需 {@code platform:tenant:write}（指定他人为首位管理员时
     *              额外需 {@code platform:user:read}）
     * @param req   企业编码、名称与可选的首位管理员（{@code null} 表示 actor 本人）
     * @return 新企业视图
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失、code/name 不合法，
     *         或首位管理员不存在、非启用账号；403 缺权限；409 企业编码重复
     */
    TenantVO createTenant(CurrentSession actor, CreateTenantDTO req);

    /**
     * 局部更新企业的名称或状态。
     *
     * <p>状态置为 {@code suspended} 时企业授权代次由触发器 +1，该企业下的活跃会话
     * 在下次权威核验被判为租户停用；仅改名不推进代次。
     *
     * @param actor    当前会话快照；需 {@code platform:tenant:write}
     * @param tenantId 目标企业 UUID 文本
     * @param req      PATCH 载荷；未提供（{@code null}）的字段不修改，可带 expected_revision
     * @return 更新后的企业视图
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID、请求体缺失或 name/status 不合法；
     *         403 缺权限；404 企业不存在；409 修订冲突
     */
    TenantVO updateTenant(CurrentSession actor, String tenantId, UpdateTenantDTO req);

    /**
     * keyset 分页列出当前企业的成员。
     *
     * @param actor     当前会话快照；需 {@code tenant:member:read} 且已选择企业上下文
     * @param tenantIdRaw 可选企业过滤，仅允许等于会话当前企业；{@code null}/空白表示用当前企业
     * @param limitRaw  单页条数，{@code null} 取默认 20，范围 1..200
     * @param cursorRaw 上一页游标（base64url 的末行成员 id），{@code null}/空白表示首页
     * @return 当前页成员视图（含账号摘要、部门与角色码）与下一页游标；
     *         该企业暂无成员时返回空列表而非报错
     * @throws com.airagent.iam.web.error.ApiException 403 缺权限或跨企业请求；
     *         400 未选择企业上下文、limit/cursor 不合法
     */
    PageVO<MemberVO> listMembers(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);

    /**
     * 向当前企业添加成员：关联既有账号，或显式新建 workforce 账号后入企业。
     *
     * <p>账号行只能由平台上下文写入，故同一事务内先以平台上下文建档/查重、
     * 再切回企业上下文写成员与角色。绝不按同名账号隐式合并：同名已存在一律 409，
     * 要求调用方显式给出 user_id；给定的 user_id 查不到账号则 400（禁止隐式建档）。
     *
     * @param actor 当前会话快照；需 {@code tenant:member:write}，带角色时还需
     *              {@code tenant:role:write}，关联既有账号时还需 {@code platform:user:read}
     * @param req   目标企业（守卫用）、user_id 或 account/display_name/password、部门与角色码集合
     * @return 新成员视图（含账号摘要与已授角色码）
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失、字段不合法、指定用户不存在、
     *         部门不属本企业，或未选择企业上下文；403 缺权限或角色越界；
     *         409 该用户已是本企业成员，或账号同名冲突
     */
    MemberVO createMembership(CurrentSession actor, CreateMembershipDTO req);

    /**
     * 局部更新成员：部门挂靠与在本企业内的状态。
     *
     * <p>状态或部门实际变化会推进成员修订号，使该账号在本企业的会话在下次权威核验被拒；
     * 停用企业最后一名有效管理员由数据库触发器硬拒（409）。部门字段是全量替换语义：
     * 请求中的 {@code null} 会把成员从部门中摘出，只想改状态时必须回传当前部门。
     *
     * @param actor           当前会话快照；需 {@code tenant:member:write} 且已选择企业上下文
     * @param membershipIdRaw 目标成员关系 UUID 文本
     * @param req             PATCH 载荷；可带 expected_revision
     * @return 更新后的成员视图
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID、请求体缺失、status/department 不合法，
     *         或未选择企业上下文；403 缺权限；404 成员不存在或不属于当前企业；
     *         409 修订冲突或触发最后管理员保护
     */
    MemberVO updateMembership(CurrentSession actor, String membershipIdRaw, UpdateMembershipDTO req);

    /**
     * 从当前企业移除成员（不删除账号本身及其平台角色）。
     *
     * <p>成员的角色关联随复合外键级联清除；若被移除者是最后一名有效企业管理员，
     * 数据库触发器硬拒（409），事务回滚且不写审计。
     *
     * @param actor           当前会话快照；需 {@code tenant:member:write} 且已选择企业上下文
     * @param membershipIdRaw 目标成员关系 UUID 文本
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID 或未选择企业上下文；
     *         403 缺权限；404 成员不存在或不属于当前企业；409 违反最后管理员保护
     */
    void deleteMembership(CurrentSession actor, String membershipIdRaw);

    /**
     * 全量替换成员在当前企业内的角色（delete-then-insert）。
     *
     * <p>只处理企业域角色（内置全局模板或本租户自定义），与平台角色接口互不相通；
     * 此处对平台超级管理员也没有豁免——每个角色的权限集合必须落在 actor 自身权限快照之内。
     * 替换生效后成员修订号被推进，该账号在本企业的旧权限快照立即失效。
     *
     * @param actor           当前会话快照；需 {@code tenant:role:write} 且已选择企业上下文
     * @param membershipIdRaw 目标成员关系 UUID 文本
     * @param req             目标角色码集合（{@code null} 或空集合表示清空）与可选 expected_revision
     * @return 更新后的成员视图，角色码为替换后的结果
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID、角色码不合法/未知/停用/跨企业/平台专属，
     *         或未选择企业上下文；403 缺权限或越界授予；404 成员不存在或不属于当前企业；
     *         409 修订冲突或撤掉最后一名有效管理员
     */
    MemberVO replaceMemberRoles(CurrentSession actor, String membershipIdRaw, MemberRolesDTO req);

    /**
     * keyset 分页列出当前企业的部门（扁平列表，层级由 parent_id 在调用方还原）。
     *
     * @param actor       当前会话快照；需 {@code tenant:department:read} 且已选择企业上下文
     * @param tenantIdRaw 可选企业过滤，仅允许等于会话当前企业；{@code null}/空白表示用当前企业
     * @param limitRaw    单页条数，{@code null} 取默认 20，范围 1..200
     * @param cursorRaw   上一页游标（base64url 的末行部门 id），{@code null}/空白表示首页
     * @return 当前页部门与下一页游标；该企业暂无部门时返回空列表而非报错
     * @throws com.airagent.iam.web.error.ApiException 403 缺权限或跨企业请求；
     *         400 未选择企业上下文、limit/cursor 不合法
     */
    PageVO<DepartmentVO> listDepartments(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);

    /**
     * 在当前企业内新建部门。
     *
     * <p>部门表没有修订列，并发守卫改用会话上下文版本：请求体的 tenant_id 与
     * expected_ctx_version 均为必填，与会话不一致即 409。上级部门必须属于同一企业，
     * 层级成环由数据库触发器拒绝；同企业内部门编码唯一，冲突返回 409。
     *
     * @param actor       当前会话快照；需 {@code tenant:department:write} 且已选择企业上下文
     * @param tenantIdRaw 查询参数给出的目标企业，仅允许等于会话当前企业
     * @param req         部门编码、名称、可选上级，以及必填的上下文守卫对
     * @return 新部门视图（状态为表默认 active）
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失、code/name 不合法、
     *         上级部门不存在或不属于本企业，或未选择企业上下文；403 缺权限或跨企业请求；
     *         409 部门编码冲突，或上下文守卫不匹配（context_changed）
     */
    DepartmentVO createDepartment(CurrentSession actor, String tenantIdRaw, CreateDepartmentDTO req);

    /**
     * 局部更新部门：名称、上级与状态。
     *
     * <p>{@code null} 组件保持原值；上级部门只能被替换为另一个同企业部门，
     * 无法借本方法把部门降级为顶级。更新范围按会话当前企业限定，跨企业 id 视为不存在（404）。
     * 上下文守卫（tenant_id 与 expected_ctx_version 必填且一致）由控制器与服务层双重裁决。
     *
     * @param actor          当前会话快照；需 {@code tenant:department:write} 且已选择企业上下文
     * @param departmentIdRaw 目标部门 UUID 文本
     * @param req            PATCH 载荷，含必填的上下文守卫对
     * @return 更新后的部门视图
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失、status/name 不合法、
     *         上级部门不属本企业，或未选择企业上下文；403 缺权限或跨企业请求；
     *         404 部门不存在或不属于当前企业；409 层级成环，或上下文守卫不匹配
     */
    DepartmentVO updateDepartment(CurrentSession actor, String departmentIdRaw, UpdateDepartmentDTO req);
}
