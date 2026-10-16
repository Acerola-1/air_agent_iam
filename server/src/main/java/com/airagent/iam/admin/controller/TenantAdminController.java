package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.CreateDepartmentDTO;
import com.airagent.iam.admin.dto.CreateMembershipDTO;
import com.airagent.iam.admin.dto.CreateTenantDTO;
import com.airagent.iam.admin.dto.MemberRolesDTO;
import com.airagent.iam.admin.dto.UpdateDepartmentDTO;
import com.airagent.iam.admin.dto.UpdateMembershipDTO;
import com.airagent.iam.admin.dto.UpdateTenantDTO;
import com.airagent.iam.admin.service.TenantAdminService;
import com.airagent.iam.admin.vo.DepartmentVO;
import com.airagent.iam.admin.vo.MemberVO;
import com.airagent.iam.admin.vo.TenantVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.web.error.ApiException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 企业、成员与部门管理 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>同一组能力挂载在两条路径上，对应两个鉴权面（子路径为 {@code /tenants}、
 * {@code /members}、{@code /departments}）：
 * <ul>
 *   <li>{@code /v1/admin/**} —— 人类 Bearer：经
 *       {@link BearerAuthInterceptor} 校验 {@code Authorization: Bearer <Sa-Token>}；</li>
 *   <li>{@code /web-api/admin/**} —— 浏览器会话：经 BrowserSessionInterceptor
 *       校验会话 Cookie，并由 CsrfOriginInterceptor 对写操作做同源防护。</li>
 * </ul>
 *
 * <p>租户隔离口径：企业管理（{@code platform:tenant:read/write}）在平台上下文执行，
 * 可跨企业；成员与部门管理（{@code tenant:member:*}、{@code tenant:department:*}、
 * {@code tenant:role:write}）一律以会话 currentTenantId 为准 —— 请求里的 tenant_id
 * 只允许缺省或与当前上下文一致，跨企业显式 403，未选择企业上下文 400。
 * 部门写操作额外要求请求体回带 tenant_id + expected_ctx_version 做表单级 CAS，
 * 由本类的 {@link #requireDepartmentContext} 先于服务层校验，不一致 409。
 *
 * <p>本层其余部分只做会话提取与参数透传；权限裁决、行锁与修订比对、最后管理员保护
 * （数据库触发器 guard_last_admin）与同事务审计全部在 {@link TenantAdminService} 实现层完成。
 * 错误统一由 GlobalExceptionHandler 转为错误信封（HTTP 状态见各操作的 {@code @ApiResponse}）。
 *
 * @author Acerola
 */
@Tag(name = "企业与组织",
        description = "企业建档与状态、企业成员（含成员角色分配）与部门层级管理。"
                + "人类 Bearer 与浏览器会话两条路径能力相同；企业/成员/部门分属平台权限码与租户权限码两套口径")
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class TenantAdminController {

    /** 企业/成员/部门业务服务。 */
    private final TenantAdminService service;

    /**
     * 构造企业与组织管理控制器。
     *
     * @param service 企业、成员、部门业务服务（权限、上下文与事务在服务层裁决）
     */
    public TenantAdminController(TenantAdminService service) {
        this.service = service;
    }

    // ------------------------------------------------ 企业

    /**
     * keyset 分页拉取全平台企业列表（平台口径）。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param limit   单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor  不透明游标（上一页末行 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @return 当前页 {@link PageVO}；无后续数据时 {@code nextCursor} 为 {@code null}；
     *         无匹配企业时 {@code items} 为空列表
     */
    @Operation(summary = "分页列出企业",
            description = "需 platform:tenant:read 权限，在平台上下文执行（可按 id 升序遍历全部企业）。"
                    + "按 id 升序 keyset 分页；authRevision 为企业授权代次，可用作更新基线。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "400", description = "limit 越界、cursor 或游标解码后的 id 不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @GetMapping("/tenants")
    public PageVO<TenantVO> listTenants(HttpServletRequest request,
                                        @Parameter(description = "单页条数 1..200，缺省 20")
                                        @RequestParam(value = "limit", required = false) Integer limit,
                                        @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                        @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listTenants(current(request), limit, cursor);
    }

    /**
     * 企业建档，并在同一事务内装配首位企业管理员。
     *
     * <p>建档分两段切换事务上下文：先在平台上下文插入 tenants 行（RLS 的 WITH CHECK 只允许
     * 平台上下文写企业行），再切到新企业上下文写成员与成员角色，最后切回平台上下文记企业级审计。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param body    建档请求；{@code null} 请求体返回 400。initialAdminUserId 省略时默认为当前操作者，
     *                显式指定他人时额外要求 platform:user:read
     * @return 201 与新企业视图（authRevision 为建档后的代次）
     */
    @Operation(summary = "创建企业",
            description = "需 platform:tenant:write 权限。code 为 2..64 位字母数字与 _-，全平台唯一（冲突 409）；name 非空且不超过 128。"
                    + "首位管理员必须是 status=active 的现有账号，否则 400；系统自动为其建立成员关系并授予内置角色 tenant_admin。"
                    + "同事务写入 admin.tenant.bootstrap 与 admin.tenant.create 两条审计。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "201", description = "创建成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失或 code/name 不合法、initial_admin_user_id 非 UUID、首位管理员不存在或已停用")
    @ApiResponse(responseCode = "403", description = "缺少 platform:tenant:write，或代他人指定管理员时缺少 platform:user:read")
    @ApiResponse(responseCode = "409", description = "企业 code 唯一冲突")
    @PostMapping("/tenants")
    public ResponseEntity<TenantVO> createTenant(HttpServletRequest request,
                                                 @RequestBody(required = false) CreateTenantDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createTenant(current(request), body));
    }

    /**
     * 按 id 查询单个企业。
     *
     * <p>平台口径（platform:tenant:read）可读任意企业；仅持企业侧读权限
     * （tenant:member:read 或 tenant:department:read）的主体只能读自己当前上下文企业，
     * 未选择企业返回 400、读他企业返回 403（不泄露该企业的存在性细节）。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      企业 UUID 文本；非 UUID 返回 400
     * @return 企业视图
     */
    @Operation(summary = "查询企业详情",
            description = "需 platform:tenant:read，或 tenant:member:read / tenant:department:read 之一（后者只能读会话当前企业）。"
                    + "行可见性另受 iam.tenants 的 RLS 约束：平台上下文、本企业管理员或该企业有效成员可见。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "400", description = "id 不是合法 UUID，或企业侧主体未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少查看权限，或请求的企业不是会话当前企业")
    @ApiResponse(responseCode = "404", description = "企业不存在或不可见")
    @GetMapping("/tenants/{id}")
    public TenantVO getTenant(HttpServletRequest request,
                              @Parameter(description = "企业 UUID") @PathVariable String id) {
        return service.getTenant(current(request), id);
    }

    /**
     * 局部更新企业（名称或状态）。
     *
     * <p>请求体中未出现的字段保持原值（SQL 侧 COALESCE 语义）；code 建档后不可改。
     * 状态变更会由企业表触发器推进 auth_revision，使该企业下所有旧会话在下一次权威核验时失效，
     * 但本接口不主动撤销 Redis 会话键（与账号停用/改密路径不同）。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      企业 UUID 文本；非 UUID 返回 400
     * @param body    PATCH 请求；{@code null} 请求体返回 400；status 仅接受 active/suspended；
     *                expectedRevision 省略表示不做并发检查
     * @return 更新后的企业视图（authRevision 为更新后的代次）
     */
    @Operation(summary = "更新企业",
            description = "需 platform:tenant:write 权限。status 仅接受 active/suspended；置为 suspended 后企业内会话"
                    + "在下次权威核验时被判定为 tenant_suspended 而失效（不即时清理 Redis 会话键）。"
                    + "可提交 expected_revision 与企业授权代次做乐观并发检查，不一致返回 409。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、name 不合法、status 非 active/suspended 或 id 非 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "企业不存在或不可见")
    @ApiResponse(responseCode = "409", description = "expected_revision 与当前企业授权代次冲突")
    @PatchMapping("/tenants/{id}")
    public TenantVO updateTenant(HttpServletRequest request,
                                 @Parameter(description = "企业 UUID") @PathVariable String id,
                                 @RequestBody(required = false) UpdateTenantDTO body) {
        return service.updateTenant(current(request), id, body);
    }

    // ------------------------------------------------ 成员

    /**
     * keyset 分页拉取当前企业的成员列表。
     *
     * <p>每行的账号摘要经 {@code iam_auth.member_user_brief} 受控读取，因此停用成员的
     * 账号信息同样可见（这是该函数存在的原因）；每行的角色码按码升序装配。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param tenantId 目标企业 UUID 文本；省略时取会话当前企业，与本租户不一致返回 403。
     *                 该参数不提供"跨企业查询"能力
     * @param limit    单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor   不透明游标（上一页末行成员 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @return 当前页 {@link PageVO}；无后续数据时 {@code nextCursor} 为 {@code null}；
     *         企业内无成员时 {@code items} 为空列表
     */
    @Operation(summary = "分页列出企业成员",
            description = "需 tenant:member:read 权限且已选择企业上下文（否则 400）。"
                    + "仅返回会话当前企业的成员；status 为成员关系状态（active/disabled），"
                    + "user.status 为账号状态，两者相互独立。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "400", description = "未选择企业上下文、tenant_id 非 UUID、limit 越界或 cursor 不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限，或 tenant_id 与会话当前企业不一致")
    @GetMapping("/members")
    public PageVO<MemberVO> listMembers(HttpServletRequest request,
                                        @Parameter(description = "企业 UUID，仅允许等于会话当前企业；省略即当前企业")
                                        @RequestParam(value = "tenant_id", required = false) String tenantId,
                                        @Parameter(description = "单页条数 1..200，缺省 20")
                                        @RequestParam(value = "limit", required = false) Integer limit,
                                        @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                        @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listMembers(current(request), tenantId, limit, cursor);
    }

    /**
     * 将账号纳入当前企业成员（关联既有账号或显式新建账号两条分支）。
     *
     * <p>users 是全局表：建档/查重一律在平台上下文进行，绝不按同名账号隐式合并 ——
     * 账号已存在时要求调用方显式传 user_id，否则 409。成员、部门、角色的落库回到本租户上下文，
     * 由 RLS、同租户复合外键与触发器共同裁决。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param body    成员请求；{@code null} 请求体返回 400。{@code user_id} 与
     *                {@code account + display_name + password} 二选一，前者优先
     * @return 201 与新成员视图（roles 为授予后的角色码）
     */
    @Operation(summary = "新增企业成员",
            description = "需 tenant:member:write 权限且已选择企业上下文。关联既有账号（user_id）额外要求 platform:user:read，"
                    + "账号不存在则 400（禁止隐式建档）；显式建档要求 account 为可打印 ASCII 3..64 且在 workforce 域内未被占用（否则 409），"
                    + "password 需通过强度校验（400）。同企业重复成员返回 409；department_id 不属于本企业返回 400；"
                    + "role_codes 只接受内置企业角色模板或本企业自定义的活跃 tenant 角色（400），且不得授予自身权限集合之外的角色（403）。"
                    + "副作用：成员角色授予会推进成员代次。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "201", description = "新增成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、字段不合法、口令强度不足、指定用户/部门不存在、角色未知或未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少 tenant:member:write / platform:user:read，或授予超出自身可授范围的角色，或跨企业写入")
    @ApiResponse(responseCode = "409", description = "账号已存在需显式 user_id，或该用户已是本企业成员")
    @PostMapping("/members")
    public ResponseEntity<MemberVO> createMembership(HttpServletRequest request,
                                                     @RequestBody(required = false) CreateMembershipDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.createMembership(current(request), body));
    }

    /**
     * 局部更新成员（部门归属或成员状态）。
     *
     * <p>并发语义要点：status 走 COALESCE（省略即保持原值），而 department_id 为直接赋值 ——
     * 请求体省略该字段或传空白会把成员部门置空（解除部门归属），与其他 PATCH 接口的语义不同。
     * 部门或状态发生变化都会由触发器推进成员代次，使该成员的旧会话在下一次权威核验时失效。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      成员关系 UUID 文本（不是 user id）；非 UUID 返回 400
     * @param body    PATCH 请求；{@code null} 请求体返回 400；status 仅接受 active/disabled；
     *                expectedRevision 省略表示不做并发检查
     * @return 更新后的成员视图
     */
    @Operation(summary = "更新企业成员",
            description = "需 tenant:member:write 权限且已选择企业上下文；目标成员必须属于当前企业（否则 404）。"
                    + "status 仅接受 active/disabled；department_id 省略或传空白会清空部门归属（置空后需重新指定才恢复）。"
                    + "可提交 expected_revision 与成员代次做乐观并发检查，不一致返回 409。"
                    + "副作用：停用成员或改变其部门都会推进成员代次。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、status 非 active/disabled、department_id 非 UUID 或不属于本企业、未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "成员不存在或不属于当前企业")
    @ApiResponse(responseCode = "409", description = "expected_revision 与当前成员代次冲突")
    @PatchMapping("/members/{id}")
    public MemberVO updateMembership(HttpServletRequest request,
                                     @Parameter(description = "成员关系 UUID") @PathVariable String id,
                                     @RequestBody(required = false) UpdateMembershipDTO body) {
        return service.updateMembership(current(request), id, body);
    }

    /**
     * 移除成员关系（不删除账号本身）。
     *
     * <p>成员关系删除后其成员角色行随外键级联清理。若目标成员是本租户最后一名有效
     * {@code tenant_admin}，数据库触发器 guard_last_admin 会以 check_violation 拒绝整体回滚。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      成员关系 UUID 文本；非 UUID 返回 400
     * @return 204 空响应体
     */
    @Operation(summary = "移除企业成员",
            description = "需 tenant:member:write 权限且已选择企业上下文。只解除成员关系，账号与其他企业成员关系不受影响。"
                    + "最后管理员保护：触发器仅统计『账号启用 + 成员关系启用 + tenant_admin 角色启用』三项同时成立的成员，"
                    + "移除本租户最后一名这样的管理员会被拒绝并整体回滚（409）。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "移除成功")
    @ApiResponse(responseCode = "400", description = "id 非 UUID 或未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "成员不存在或不属于当前企业")
    @ApiResponse(responseCode = "409", description = "违反最后管理员保护等业务约束")
    @DeleteMapping("/members/{id}")
    public ResponseEntity<Void> deleteMembership(HttpServletRequest request,
                                                 @Parameter(description = "成员关系 UUID") @PathVariable String id) {
        service.deleteMembership(current(request), id);
        return ResponseEntity.noContent().build();
    }

    /**
     * 全量替换成员的企业角色。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      成员关系 UUID 文本；非 UUID 返回 400
     * @param body    目标角色码集合；{@code null} 或空集合表示清空该成员的全部企业角色
     * @return 更新后的成员视图（roles 为替换后的结果，按码升序）
     */
    @Operation(summary = "替换成员企业角色",
            description = "需 tenant:role:write 权限且已选择企业上下文。角色码须为内置企业角色模板或本企业的活跃 tenant 角色，"
                    + "平台角色与跨企业角色一律拒绝（400），且每个角色的权限集合必须落在操作者自身权限集合之内（403）。"
                    + "delete-then-insert 同事务完成；每次角色增删都会推进成员代次，"
                    + "移除本租户最后一名有效 tenant_admin 会被触发器拒绝（409）。可提交 expected_revision 做乐观并发检查。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "替换成功")
    @ApiResponse(responseCode = "400", description = "角色码不合法或未知，或 id 非 UUID、未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少 tenant:role:write，或授予超出自身可授范围的角色")
    @ApiResponse(responseCode = "404", description = "成员不存在或不属于当前企业")
    @ApiResponse(responseCode = "409", description = "expected_revision 冲突，或违反最后管理员保护")
    @PostMapping("/members/{id}/roles")
    public MemberVO replaceMemberRoles(HttpServletRequest request,
                                       @Parameter(description = "成员关系 UUID") @PathVariable String id,
                                       @RequestBody(required = false) MemberRolesDTO body) {
        return service.replaceMemberRoles(current(request), id, body);
    }

    // ------------------------------------------------ 部门

    /**
     * keyset 分页拉取当前企业的部门列表（扁平结果，不含树形组装）。
     *
     * @param request  当前 HTTP 请求（会话快照由拦截器注入）
     * @param tenantId 目标企业 UUID 文本；省略时取会话当前企业，与本租户不一致返回 403
     * @param limit    单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor   不透明游标（上一页末行部门 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @return 当前页 {@link PageVO}；无后续数据时 {@code nextCursor} 为 {@code null}；
     *         企业尚无部门时 {@code items} 为空列表
     */
    @Operation(summary = "分页列出部门",
            description = "需 tenant:department:read 权限且已选择企业上下文（否则 400）。"
                    + "部门明细仅在当前企业上下文内可见（跨企业成员身份不扩展部门读权限）。结果按 id 升序，不裁剪停用部门。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "400", description = "未选择企业上下文、tenant_id 非 UUID、limit 越界或 cursor 不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限，或 tenant_id 与会话当前企业不一致")
    @GetMapping("/departments")
    public PageVO<DepartmentVO> listDepartments(HttpServletRequest request,
                                                @Parameter(description = "企业 UUID，仅允许等于会话当前企业；省略即当前企业")
                                                @RequestParam(value = "tenant_id", required = false) String tenantId,
                                                @Parameter(description = "单页条数 1..200，缺省 20")
                                                @RequestParam(value = "limit", required = false) Integer limit,
                                                @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                                @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listDepartments(current(request), tenantId, limit, cursor);
    }

    /**
     * 在当前企业下新建部门。
     *
     * <p>部门写操作走"表单级 CAS"：query 与 body 各带一份 tenant_id —— query 那份用于服务层
     * 解析作用域租户（可省略），body 那份连同 expected_ctx_version 是本类与服务层双重校验的对象，
     * 两者都必须与会话当前企业上下文一致，且 ctxVersion 必须精确等于会话代次。
     *
     * @param request  当前 HTTP 请求（会话快照由拦截器注入）
     * @param tenantId 目标企业 UUID（query）；省略时取会话当前企业，与本租户不一致返回 403
     * @param body     建部门请求；{@code null} 请求体、缺失 tenant_id 或 expected_ctx_version 均返回 400；
     *                 parentId 省略或空白表示建为顶级部门
     * @return 201 与新部门视图
     */
    @Operation(summary = "创建部门",
            description = "需 tenant:department:write 权限。请求体必须回带与会话一致的 tenant_id 和 expected_ctx_version，"
                    + "任一缺失返回 400，任一不一致返回 409（context_changed）。code 为 1..64 位字母数字与 _-，"
                    + "在企业内唯一（冲突 409）；name 非空且不超过 128；parent_id 必须存在且属于本企业（否则 400）。"
                    + "同租户父级约束由复合外键与无环触发器兜底。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "201", description = "创建成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、tenant_id/expected_ctx_version 未回带、code/name/parent_id 不合法或未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少 tenant:department:write，或目标企业不是会话当前企业")
    @ApiResponse(responseCode = "409", description = "表单企业上下文已变化（context_changed），或部门 code 企业内唯一冲突/层级约束违例")
    @PostMapping("/departments")
    public ResponseEntity<DepartmentVO> createDepartment(HttpServletRequest request,
                                                          @Parameter(description = "企业 UUID，仅允许等于会话当前企业；省略即当前企业")
                                                          @RequestParam(value = "tenant_id", required = false) String tenantId,
                                                          @RequestBody(required = false) CreateDepartmentDTO body) {
        requireDepartmentContext(current(request), body == null ? null : body.tenantId(),
                body == null ? null : body.expectedCtxVersion());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.createDepartment(current(request), tenantId, body));
    }

    /**
     * 局部更新部门（名称、父级或状态）。
     *
     * <p>parentId 三态语义（与 status/name 的 COALESCE 保持原值不同）：字段省略 → 保持原父级；
     * 传空串 → 显式把父级置空、该部门升为顶级；传 UUID → 改挂到该企业内的该部门下。
     * 层级无环由数据库触发器 reject_department_cycle 兜底（含自环），违例返回 409。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      部门 UUID 文本；非 UUID 返回 400
     * @param body    PATCH 请求；{@code null} 请求体、缺失 tenant_id 或 expected_ctx_version 均返回 400；
     *                status 仅接受 active/disabled；name 省略表示保持原值
     * @return 更新后的部门视图
     */
    @Operation(summary = "更新部门",
            description = "需 tenant:department:write 权限且已选择企业上下文；目标部门必须属于当前企业（否则 404）。"
                    + "请求体必须回带与会话一致的 tenant_id 与 expected_ctx_version，缺失 400、不一致 409（context_changed）。"
                    + "status 仅接受 active/disabled；parent_id 省略保持原父级、传空串升为顶级、传 UUID 改挂父级"
                    + "（须为本企业部门，否则 400）；层级成环或唯一冲突返回 409。部门变更不推进任何授权代次。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、tenant_id/expected_ctx_version 未回带、status 非法、parent_id 不存在或不属于本企业、未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少 tenant:department:write")
    @ApiResponse(responseCode = "404", description = "部门不存在或不属于当前企业")
    @ApiResponse(responseCode = "409", description = "表单企业上下文已变化，或层级成环等约束违例")
    @PatchMapping("/departments/{id}")
    public DepartmentVO updateDepartment(HttpServletRequest request,
                                         @Parameter(description = "部门 UUID") @PathVariable String id,
                                         @RequestBody(required = false) UpdateDepartmentDTO body) {
        requireDepartmentContext(current(request), body == null ? null : body.tenantId(),
                body == null ? null : body.expectedCtxVersion());
        return service.updateDepartment(current(request), id, body);
    }

    // ---------------------------------------------------------------- 内部辅助

    /**
     * 校验部门写请求回带的企业上下文基线（表单级乐观并发检查）。
     *
     * <p>该检查先于服务层的权限裁决执行，目的是让前端在企业切换后立刻拿到 409 并刷新表单，
     * 避免把部门写进错误企业。服务层另有口径更宽的同类复核（字段缺省时跳过）。
     *
     * @param actor           当前会话快照
     * @param tenantId        请求体声明的企业 UUID 文本
     * @param expectedVersion 请求体声明的会话上下文代次（对应 {@code CurrentSession.ctxVersion}）
     * @throws ApiException 400 当任一字段缺失（{@code null}）；409（context_changed）当声明的企业
     *                      与会话当前企业不符，或声明代次不等于会话代次（会话未选企业时同样 409）
     */
    private void requireDepartmentContext(CurrentSession actor, String tenantId, Long expectedVersion) {
        if (tenantId == null || expectedVersion == null) {
            throw ApiException.badRequest("tenant_id 与 expected_ctx_version 必填");
        }
        if (actor.currentTenantId() == null || !actor.currentTenantId().toString().equals(tenantId)
                || actor.ctxVersion() != expectedVersion) {
            throw ApiException.contextChanged("表单企业上下文已变化，请刷新后重试");
        }
    }

    /**
     * 取回拦截器注入的请求级会话快照。
     *
     * <p>仅对受保护路径有效；快照已经过 Redis Sa-Token 与 PG 权威双重核验。
     * 若拦截器未注入（配置外路径），返回 {@code null}，由服务层按未授权拒绝。
     *
     * @param request 当前 HTTP 请求
     * @return 已核验的 {@link CurrentSession}，可能为 {@code null}
     */
    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
