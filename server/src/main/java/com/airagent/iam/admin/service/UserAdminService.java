package com.airagent.iam.admin.service;

import com.airagent.iam.admin.dto.CreateUserDTO;
import com.airagent.iam.admin.dto.PlatformRolesDTO;
import com.airagent.iam.admin.dto.ResetPasswordDTO;
import com.airagent.iam.admin.dto.UpdateUserDTO;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/**
 * 平台账号生命周期与平台角色分配的业务接口（Service 层）。
 *
 * <p>所有方法以已通过双重核验的 {@link CurrentSession} 为 actor，在实现内部逐一裁决
 * {@code platform:user:*} 权限、开启事务并设置 PostgreSQL 请求上下文（RLS），
 * 写操作与审计在同一事务提交。失败统一抛
 * {@link com.airagent.iam.web.error.ApiException}，由全局处理器映射 HTTP 状态。
 *
 * @author Acerola
 */
public interface UserAdminService {

    /**
     * keyset 分页列出 actor 可见的平台账号。
     *
     * @param actor  当前会话快照；需 {@code platform:user:read}
     * @param limit  单页条数，{@code null} 取默认 20，范围 1..200
     * @param cursor 上一页游标（base64url 的末行 id），{@code null}/空白表示首页
     * @param query  可选账号子串过滤，大小写不敏感；{@code null} 表示不过滤
     * @return 当前页数据与下一页游标（无更多时为 {@code null}）
     * @throws com.airagent.iam.web.error.ApiException 403 缺权限；400 limit/cursor 不合法
     */
    PageVO<UserVO> list(CurrentSession actor, Integer limit, String cursor, String query);

    /**
     * 查询单个平台账号详情。
     *
     * @param actor  当前会话快照；需 {@code platform:user:read}
     * @param userId 目标用户 UUID 文本
     * @return 账号视图，含其平台角色码列表
     * @throws com.airagent.iam.web.error.ApiException 400 非 UUID；403 缺权限；404 不存在或 RLS 不可见
     */
    UserVO get(CurrentSession actor, String userId);

    /**
     * 创建平台账号（realm 固定 workforce）。
     *
     * @param actor   当前会话快照；需 {@code platform:user:write}
     * @param request 账号、显示名与初始明文口令（仅用于生成 BCrypt 摘要，不落明文）
     * @return 新账号视图
     * @throws com.airagent.iam.web.error.ApiException 400 字段不合法或请求体缺失；403 缺权限；409 账号名重复
     */
    UserVO create(CurrentSession actor, CreateUserDTO request);

    /**
     * 局部更新账号显示名或状态。
     *
     * <p>状态置为 {@code disabled} 时撤销目标全部活跃会话（含其当前会话），
     * 会话键经 outbox 异步清理；仅改显示名不推进授权代次。
     *
     * @param actor   当前会话快照；需 {@code platform:user:write}
     * @param userId  目标用户 UUID 文本
     * @param request PATCH 载荷；未提供（{@code null}）的字段不修改，可带 expected_revision
     * @return 更新后的账号视图
     * @throws com.airagent.iam.web.error.ApiException 400 字段不合法；403 缺权限；404 不存在；409 修订冲突
     */
    UserVO update(CurrentSession actor, String userId, UpdateUserDTO request);

    /**
     * 管理员重置目标账号口令。
     *
     * <p>改密会使目标全部会话（含当前会话）失效：口令变更触发授权代次推进，
     * 随后显式撤销活跃会话并将 Redis 键删除写入同事务 outbox。
     *
     * @param actor   当前会话快照；需 {@code platform:user:password:reset}
     * @param userId  目标用户 UUID 文本
     * @param request 新明文口令与可选 expected_revision
     * @throws com.airagent.iam.web.error.ApiException 400 口令缺失或强度不足；403 缺权限；404 不存在；409 修订冲突
     */
    void resetPassword(CurrentSession actor, String userId, ResetPasswordDTO request);

    /**
     * 全量替换账号的平台角色。
     *
     * <p>非 {@code platform_super_admin} 的 actor 只能授予自身权限集合之内的角色；
     * 替换生效后关联主体的授权代次被推进，旧快照授权即刻失效。
     *
     * @param actor   当前会话快照；需 {@code platform:user:role:assign}
     * @param userId  目标用户 UUID 文本
     * @param request 目标角色码集合（{@code null} 或空集合表示清空）与可选 expected_revision
     * @return 更新后的账号视图
     * @throws com.airagent.iam.web.error.ApiException 400 角色码不合法/未知/停用；403 缺权限或越界授予；404 不存在；409 修订冲突
     */
    UserVO replacePlatformRoles(CurrentSession actor, String userId, PlatformRolesDTO request);
}
