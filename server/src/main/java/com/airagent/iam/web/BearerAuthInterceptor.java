package com.airagent.iam.web;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.web.error.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 人类 Bearer 令牌拦截器（Web 层，挂载 /v1/auth/** 与 /v1/admin/**，登录/登出除外）。
 *
 * <p>校验为双重权威：先取 Bearer 令牌交 SessionService 做 Sa-Token Redis
 * 存在性 + PG 主库权威快照核验（{@code requireCurrent}），通过后把
 * {@link CurrentSession} 与原始令牌放入请求属性供控制器/服务层取用。
 * 任何依赖异常（Redis/PG 不可达）不在此捕获，由全局异常处理器统一转 503——
 * 失败关闭，绝不降级放行。身份响应附加 no-store 禁止缓存。
 *
 * @author Acerola
 */
@Component
public class BearerAuthInterceptor implements HandlerInterceptor {

    /** 请求属性键：已通过双检验证的会话快照（控制器经 current() 读取）。 */
    public static final String CURRENT_SESSION_ATTRIBUTE = "iam.currentSession";
    /** 请求属性键：原始 Bearer 令牌文本（登出等需撤销自身的端点使用）。 */
    public static final String RAW_TOKEN_ATTRIBUTE = "iam.rawToken";
    /** Authorization 头前缀（含尾随空格）。 */
    private static final String BEARER_PREFIX = "Bearer ";

    /** 会话权威核验服务（Redis+PG 双检）。 */
    private final SessionService sessionService;

    /**
     * 构造拦截器。
     *
     * @param sessionService 会话权威核验服务
     */
    public BearerAuthInterceptor(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /**
     * 从请求头提取 Bearer 令牌（供登出等场景复用同一提取规则）。
     *
     * @param request 当前请求
     * @return 去掉前缀并 trim 后的令牌文本
     * @throws ApiException 401：缺失 Authorization 头、无 Bearer 前缀或令牌为空
     */
    public static String bearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            throw ApiException.unauthenticated("缺少 Bearer 访问令牌");
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            throw ApiException.unauthenticated("访问令牌为空");
        }
        return token;
    }

    /**
     * 前置校验：提取令牌 → 双检 → 注入请求属性 → 禁缓存头。
     *
     * @param request  当前请求
     * @param response 当前响应（写入 Cache-Control/Pragma）
     * @param handler  MVC 处理器（未使用）
     * @return 恒为 {@code true}；校验不通过时以 {@link ApiException} 中断
     * @throws ApiException 401 令牌缺失/为空/会话失效；依赖故障经全局处理器转 503
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String token = bearerToken(request);
        CurrentSession current = sessionService.requireCurrent(token);
        request.setAttribute(CURRENT_SESSION_ATTRIBUTE, current);
        request.setAttribute(RAW_TOKEN_ATTRIBUTE, token);
        // 身份响应一律不进浏览器/中间件缓存
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        return true;
    }
}
