package com.airagent.iam.audit.controller;

import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.service.AuditService;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 审计日志查询 HTTP 入口（Controller 层，不访问数据库，也不做权限裁决）。
 *
 * <p>同一个只读能力挂在两条路径上，对应两个鉴权面（挂载关系见
 * {@link com.airagent.iam.config.WebMvcConfiguration}）：
 * <ul>
 *   <li>{@code /v1/admin/audit-logs} —— 人类 Bearer：由 {@link BearerAuthInterceptor}
 *       校验请求头里的 Bearer 会话令牌（Redis 存活 + PG 权威快照双检）；</li>
 *   <li>{@code /web-api/admin/audit-logs} —— 浏览器会话：由 BrowserSessionInterceptor
 *       校验会话 Cookie 并以同一个 attribute key 写入会话快照；GET 属安全方法，
 *       CsrfOriginInterceptor 对其短路，不需要 CSRF 令牌。</li>
 * </ul>
 * 两个面的能力、参数与响应完全一致，差异只在凭据形态。
 *
 * <p>本层只做三件事：取拦截器注入的 {@link CurrentSession}、把三个查询参数装配成
 * {@link AuditLogQueryDTO}（越界即在构造瞬间转 400）、委托
 * {@link AuditService#list}。权限码裁决、RLS 上下文、keyset 分页与出参装配都在服务层。
 *
 * <p>可见范围不接受调用方指定：本入口没有 {@code tenant_id} 之类的归属参数，未声明的
 * 查询串一律被忽略，能看哪些审计行只由会话权限码与 PostgreSQL RLS 决定。
 * 错误统一由 GlobalExceptionHandler 转错误信封；{@code Cache-Control: no-store}
 * 由两个拦截器强制，审计响应不进缓存。
 *
 * @author Acerola
 */
@Tag(name = "审计日志",
        description = "平台与企业审计日志的有界分页查询（只读）。人类 Bearer 与浏览器会话两条路径能力相同；"
                + "可见范围由权限码 platform:audit:read / tenant:audit:read 与 PostgreSQL RLS 决定，不接受调用方指定租户")
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class AuditController {

    /** 审计查询服务 */
    private final AuditService auditService;

    /**
     * 构造审计查询控制器。
     *
     * @param auditService 审计查询服务（权限裁决、RLS 上下文与分页装配都在其中完成）
     */
    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    /**
     * keyset 分页拉取当前会话可见的审计日志（最新在前）。
     *
     * @param request 当前 HTTP 请求；会话快照取拦截器写入的请求属性
     *                {@link BearerAuthInterceptor#CURRENT_SESSION_ATTRIBUTE}，
     *                两个鉴权面写入的是同一个 key
     * @param limit 单页条数；{@code null} 时取默认 20，合法范围 1..200（含），越界返回 400，
     *              不静默截断
     * @param cursor 不透明游标（上一页末行审计 id 的 base64url 文本）；{@code null} 或空白表示
     *               从最新一行开始；无法解码或不大于 0 返回 400
     * @param action 动作码过滤模式，最长 128 字符；{@code null} 表示不过滤（空串会作为空 LIKE
     *               模式，命中不到任何行）。SQL LIKE 语义、大小写敏感，其中 {@code *}
     *               由服务层转为多字符通配符
     * @return 当前页 {@link PageVO}，元素为 {@link AuditLogVO}，按审计行 id 降序；
     *         无更多数据时 {@code nextCursor} 为 {@code null}，命中 0 条时 {@code items} 为空列表
     */
    @Operation(summary = "分页查询审计日志",
            description = "需要 platform:audit:read 或 tenant:audit:read 之一（或语义，命中即通过）。"
                    + "持平台审计权的会话按平台口径查询，可见全部审计行（含 tenant_id 为空的平台级事件与其他租户事件）；"
                    + "仅持企业审计权的会话按会话当前企业口径查询，RLS 只放行本租户行，且未选择企业上下文时返回 400。"
                    + "按 id 降序 keyset 分页（不支持时间范围、操作者或目标对象过滤）。"
                    + "detail 为落库 JSONB 原文，写入方约定只含 id/名称/角色码/状态/受众/原因等非秘密值。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（含命中 0 条）")
    @ApiResponse(responseCode = "400",
            description = "limit 越界、cursor 不合法、action 超长，或仅持企业审计权限但会话未选择企业上下文")
    @ApiResponse(responseCode = "401", description = "缺少或已失效的 Bearer 令牌 / 浏览器会话句柄")
    @ApiResponse(responseCode = "403", description = "两个审计权限码都不具备")
    @ApiResponse(responseCode = "503", description = "Redis 或 PostgreSQL 依赖故障，失败关闭")
    @GetMapping("/audit-logs")
    public PageVO<AuditLogVO> list(HttpServletRequest request,
                                @Parameter(description = "单页条数 1..200，缺省 20")
                                @RequestParam(value = "limit", required = false) Integer limit,
                                @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                @RequestParam(value = "cursor", required = false) String cursor,
                                @Parameter(description = "动作码 LIKE 模式（* 为通配），最长 128 字符")
                                @RequestParam(value = "action", required = false) String action) {
        CurrentSession actor = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        return auditService.list(actor, new AuditLogQueryDTO(limit, cursor, action));
    }
}
