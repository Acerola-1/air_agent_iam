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

/**
 * 角色定义、权限目录与可授权限树的业务接口（Service 层）。
 *
 * <p>所有方法以已通过 Redis 与 PostgreSQL 双重核验的 {@link CurrentSession} 为 actor，
 * 在实现内部逐一裁决权限、开启事务并设置请求上下文（RLS）。授权面按 {@code scope} 成对分离：
 * 平台线用 {@code platform:role:read|write}（上下文为企业为空、is_platform 为真），
 * 企业线用 {@code tenant:role:read|write}（上下文必须是会话当前企业），
 * 任何一侧都不能越面读写对方的角色；角色与企业的归属边界最终由 RLS 与
 * {@code guard_role_assignment_boundary} 触发器兜底。
 *
 * <p>写操作与审计在同一事务提交，审计失败整体回滚。角色与其权限集合的变化都会由数据库触发器
 * 推进引用主体（账号 auth_revision、成员 revision）的授权代次，使旧权限快照立即失效——
 * 因此角色编辑没有单独的“撤销会话”步骤，也不接受乐观并发基线。
 * 失败统一抛 {@link com.airagent.iam.web.error.ApiException}，由全局处理器映射 HTTP 状态。
 *
 * @author Acerola
 */
public interface RoleAdminService {

    /**
     * keyset 分页列出 actor 可见的角色。
     *
     * <p>显式scope=tenant始终限定当前企业与全局企业模板；仅有企业读权限时同样如此。
     * 平台读权限且未指定企业域时可查询平台全局可见集。每行追加权限码列表。
     *
     * @param actor  当前会话快照；需 {@code platform:role:read} 或 {@code tenant:role:read} 之一
     * @param scope 可选角色域；platform要求平台读权限，tenant要求已选企业；省略时按主体权限选查询面
     * @param limit  单页条数，{@code null} 取默认 20，范围 1..200
     * @param cursor 上一页游标（base64url 的末行 id），{@code null}/空白表示首页
     * @return 当前页数据与下一页游标（无更多时为 {@code null}）
     * @throws com.airagent.iam.web.error.ApiException 403 两个读权限都缺；400 limit/cursor/scope 不合法，
     *         或仅有企业读权限却未选择企业上下文
     */
    PageVO<RoleVO> listRoles(CurrentSession actor, String scope, Integer limit, String cursor);

    /**
     * 创建自定义角色，可选地一并写入初始权限集合。
     *
     * <p>{@code scope} 决定授权面与归属：platform 角色落平台上下文且企业为空，
     * tenant 角色只能落本租户自定义范围；角色插入与权限写入同事务，
     * 权限校验不通过则角色整体不生成。
     *
     * @param actor   当前会话快照；platform 需 {@code platform:role:write}，
     *                tenant 需 {@code tenant:role:write}
     * @param request 域、角色码、名称、说明与初始权限码集合（{@code null} 组件按缺省处理）
     * @return 新角色视图，含其权限码列表
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失、scope 非法、code/name 不合法，
     *         或 tenant 域未选择企业、权限码未知；403 缺对应写权限或授予自身不持有的权限；
     *         409 角色码冲突、或权限超出该角色可授范围（资源型/平台专属）
     */
    RoleVO createRole(CurrentSession actor, CreateRoleDTO request);

    /**
     * 局部更新角色的名称、说明或状态；域、角色码与归属企业不可改。
     *
     * <p>授权面依据角色自身的 scope 判定，而非请求参数，因此不存在“越面改平台角色”的路径。
     * 内置角色一律拒绝；状态变化会推进所有引用该角色的主体授权代次。
     *
     * @param actor   当前会话快照；按角色 scope 需 {@code platform:role:write} 或
     *                {@code tenant:role:write}
     * @param roleId  角色 UUID 文本
     * @param request PATCH 载荷；{@code null} 组件保持原值，请求体本身不可缺省
     * @return 更新后的角色视图
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID、请求体缺失、name/status 不合法，
     *         或企业角色操作前未选择企业；403 内置角色、缺对应写权限、或角色属他企业；404 角色不存在或不可见
     */
    RoleVO updateRole(CurrentSession actor, String roleId, UpdateRoleDTO request);

    /**
     * 全量替换角色的权限集合（delete-then-insert）。
     *
     * <p>非平台超级管理员的 actor 只能授出自身权限快照之内的权限码；企业角色还只能持有
     * 可下放到企业的权限。替换后引用该主体的授权代次被推进，旧权限快照即刻失效。
     *
     * @param actor   当前会话快照；按角色 scope 需 {@code platform:role:write} 或
     *                {@code tenant:role:write}
     * @param roleId  角色 UUID 文本
     * @param request 目标权限码集合（{@code null} 或空集合表示清空）
     * @return 更新后的角色视图，权限码为替换后的结果
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID 或权限码不合法/未知；
     *         403 内置角色、缺写权限或越界授予；404 角色不存在或不可见；
     *         409 权限不在该角色可授范围（资源型权限、企业角色拿平台专属权限）
     */
    RoleVO replacePermissions(CurrentSession actor, String roleId, RolePermissionsDTO request);

    /**
     * 读取权限目录（不分页），供角色编辑界面展示。
     *
     * <p>资源型权限（绑定资源编码者）在资源开通能力落地前不进目录；
     * 具备平台读权限者见全目录（含平台专属权限），仅具企业读权限者只见企业域权限。
     *
     * @param actor 当前会话快照；需 {@code platform:role:read} 或 {@code tenant:role:read} 之一
     * @return 按目录排序返回的权限列表；无可见权限时为空列表
     * @throws com.airagent.iam.web.error.ApiException 403 两个读权限都缺；400 仅有企业读权限却未选择企业上下文
     */
    List<PermissionVO> listPermissions(CurrentSession actor);

    /**
     * 读取 actor 的可授权限树（按域分组），是角色编辑与授权界面的唯一可选集来源。
     *
     * <p>分组规则：具备平台面读或写权限时返回平台组，具备企业面读或写权限（或具备平台组）时
     * 返回企业组；组内叶子再按 actor 自身权限快照裁剪，仅平台超级管理员看到未持有的码。
     * 资源型权限整组缺席。
     *
     * @param actor 当前会话快照；需四个角色相关权限码中的任一个
     * @return 分组后的可授权限树；权限快照不含任何可授码时各组的叶子为空列表
     * @throws com.airagent.iam.web.error.ApiException 403 四个角色权限码全缺；400 仅有企业面权限却未选择企业上下文
     */
    GrantableTreeVO grantableTree(CurrentSession actor);
}
