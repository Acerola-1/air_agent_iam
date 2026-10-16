package com.airagent.iam.internal.service;

import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.security.internal.InternalClient;

/**
 * 内部双主体身份核验业务（Service 接口层）。
 *
 * <p>分层位置：{@code /v1/internal/identity/introspect} 唯一的用例入口，实现见
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl}。
 * Controller 只负责凭据透传与异步预算，客户端注册受众、scope、限流之外的全部判定在此层及其实现中完成。
 *
 * <p>"实时"的含义：每次调用都读 PostgreSQL 主库权威快照，人类主体另加一次 Redis Sa-Token
 * 存活性检查，任何正向授权结果都不跨请求缓存。<b>两者必须同时成立才判 active</b>——
 * PG 说会话有效但 Redis 键已消失（撤销/清理），同样返回 {@code inactive}，失败关闭。
 *
 * <p>判定链（自外向内，全部为"任一不成立即拒绝"）：
 * <ol>
 *   <li>请求受众必须在调用客户端的注册受众白名单内，否则 403；</li>
 *   <li>权威快照 {@code status}：会话不存在 → 转入服务账号（机器令牌）分支；非 {@code ok}
 *       → {@code active:false} 并给出映射后的 reason；</li>
 *   <li>授权代次基线：当前用户/企业/成员代次高于会话登记基线，或会话已过 idle/绝对上界，
 *       由数据库判为 {@code invalid_or_revoked}；</li>
 *   <li>受众匹配：非 {@code langgraph-runtime} 请求受众必须等于会话登录受众（runtime 是受控的
 *       服务端派生受众，可跨登录受众核验），否则 403；</li>
 *   <li>Redis 存活：摘要对应的 Sa-Token 登录 id 必须等于快照用户 id，否则失效；</li>
 *   <li>{@code expected_context} 一致性：不一致直接 409，不回新上下文。</li>
 * </ol>
 *
 * @author Acerola
 */
public interface IntrospectionService {

    /**
     * inactive 响应的结构版本标识，写入 {@code schema_version} 字段，与契约中的
     * {@code iam.introspection.v1} 一致。active 身份视图使用另一标识
     * {@code iam.identity.v1}（见 {@link com.airagent.iam.auth.IdentityAssembler}）。
     */
    String INTROSPECTION_SCHEMA = "iam.introspection.v1";

    /**
     * 受控的服务端派生受众标识：长运行运行时（LangGraph）专用。
     *
     * <p>只有该受众可以登记/复查执行上下文并换 rt-v1 票据；令牌内省在该受众下允许跨会话
     * 登录受众核验，其余受众必须与被核验令牌的登录受众严格相同。
     */
    String RUNTIME_AUDIENCE = "langgraph-runtime";

    /**
     * 核验一个主体令牌，或复查一个已登记的执行上下文。
     *
     * <p>形态选择：{@code request.executionContext} 非空走引用复查模式，否则走令牌内省模式；
     * 二者同时给出或同时缺失返回 400。
     *
     * <p>返回体是多态的，调用方按 {@code audience} 与请求形态分支（故声明为 {@code Object}）：
     * <ul>
     *   <li>人类令牌有效：{@link com.airagent.iam.auth.vo.IdentityVO}；
     *       若 {@code include_execution_context=true}，则为 identity 与
     *       {@code execution_context} 合并后的 JSON 对象；</li>
     *   <li>服务账号令牌有效：{@link com.airagent.iam.internal.vo.ServiceIdentityVO}；</li>
     *   <li>令牌模式失效：{@link com.airagent.iam.internal.vo.InactiveIntrospectionVO}（HTTP 仍为 200）；</li>
     *   <li>引用复查：{@link com.airagent.iam.internal.vo.RecheckActiveVO} 或
     *       {@link com.airagent.iam.internal.vo.RecheckInactiveVO}。</li>
     * </ul>
     *
     * <p>引用复查不重新授予更大权限，也不延长任何有效期；机器主体不支持执行上下文与
     * {@code expected_context}（携带返回 400）。
     *
     * @param client  已完成凭据核验的内部客户端（提供 clientId、scope 与注册受众白名单）；不可为 {@code null}
     * @param request 核验请求；{@code null} 或 {@code audience} 空白返回 400
     * @return 上述多态响应体之一，不为 {@code null}
     * @throws com.airagent.iam.web.error.ApiException 400 形态不合法／UUID 不合法／runtime 专属字段被其他受众使用；
     *                      403 客户端未注册该受众、令牌受众与请求不一致、服务账号未注册该受众；
     *                      409 {@code expected_context} 与当前会话上下文不一致；
     *                      503 引用修订解析或序列化失败、权威依赖不可用
     */
    Object introspect(InternalClient client, IntrospectDTO request);

    /**
     * 加载人类会话的权威快照，并叠加 Redis 存活判定。
     *
     * <p>这是令牌内省与运行签票共用的唯一人类主体核验入口：先读 PG 主库快照，快照判
     * {@code ok} 后再确认 Sa-Token 在 Redis 中仍指向同一用户；只要 Redis 侧不再存活，
     * 返回值即被改写为 {@code invalid_or_revoked}，调用方无从区分"PG 有效但会话已失联"。
     * 服务账号等机器令牌没有会话记录，快照状态为 {@code missing}。
     *
     * @param digest 令牌原文的 SHA-256 十六进制摘要（不传原始令牌）；{@code null} 不视为有效摘要，
     *               结果为 {@code missing}
     * @return 权威快照视图，永不为 {@code null}；可用性由
     *         {@link AuthoritySnapshot#usable()} 判定，本方法不抛未授权异常
     */
    AuthoritySnapshot loadHumanSnapshot(String digest);
}
