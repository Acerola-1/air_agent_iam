package com.airagent.iam.serviceaccount.service;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.dto.UpdateServiceAccountDTO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountDetailVO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;

/**
 * 服务账号与凭据生命周期业务（Service 层契约，Controller 与 Mapper 之间）。
 *
 * <p>分层与场景：本接口覆盖“平台级服务账号”的全部管理能力——建档、分页查询、详情、
 * 停用/启用、签发凭据（含轮换）与吊销凭据，由
 * {@link com.airagent.iam.serviceaccount.controller.ServiceAccountAdminController} 在
 * {@code /v1/admin/service-accounts} 与 {@code /web-api/admin/service-accounts} 两条路径上调用。
 * 机器身份的使用侧（内部客户端核验令牌）不在此接口内，见
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl}。
 *
 * <p>统一约定（实现见 {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl}）：
 * <ul>
 *   <li>每个方法都以会话权限快照裁决 {@code platform:service:write}，actor 为 {@code null}
 *       同样按缺少权限拒绝；</li>
 *   <li>数据库操作在 {@code TransactionTemplate} 内执行，事务第一步设置平台请求上下文
 *       （企业为空），行可见性交由 RLS 裁决；</li>
 *   <li>审计与业务变更同事务写入，审计失败整体回滚；</li>
 *   <li>明文密钥只在 {@link #issueToken} 的返回值中出现一次，库内只存 SHA-256 摘要；</li>
 *   <li>不合法入参、冲突与依赖故障分别以 400/404/409/503 等语义的
 *       {@link com.airagent.iam.web.error.ApiException} 抛出，由 GlobalExceptionHandler
 *       转为统一错误信封。</li>
 * </ul>
 *
 * @author Acerola
 */
public interface ServiceAccountService {

    /**
     * 创建服务账号主体（不签发凭据）。
     *
     * <p>校验账号名格式与企业可用性后，在同一事务内插入账号行、逐条写入权限授予并记审计。
     *
     * @param actor 当前会话快照；须持有 {@code platform:service:write}，为 {@code null} 按 403 处理
     * @param req   建档请求；{@code null} 返回 400。其中租户 UUID、受众、有效期与权限码各自校验，
     *              {@code expiresInDays} 为 {@code null} 时取默认 90 天
     * @return 新建账号视图（当场拼装，{@code status} 为 active、{@code revision} 为 1）
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失或字段不合法、目标企业非 active；
     *         403 缺少权限；409 账号名唯一冲突或违反数据库业务约束
     */
    ServiceAccountVO create(CurrentSession actor, CreateServiceAccountDTO req);

    /**
     * 签发一枚新凭据（首次签发与轮换共用）。
     *
     * <p>在账号行锁内调用受控签发函数：新凭据代次为“已有最大值 + 1”，重叠窗口写入被取代的
     * 旧凭据（零窗口时旧凭据立即吊销），新凭据自身不带窗口。
     *
     * @param actor            当前会话快照；须持有 {@code platform:service:write}
     * @param serviceAccountId 服务账号 UUID 文本；非 UUID 返回 400，账号不存在返回 404
     * @param req              签发请求；{@code null} 等价零窗口。{@code overlapHours} 为
     *                         {@code null} 或 0 表示立即撤销旧凭据，范围 0..24
     * @return 签发结果，含仅此一次披露的明文密钥、到期时间与施加于旧凭据的重叠上界
     * @throws com.airagent.iam.web.error.ApiException 400 id 非 UUID 或窗口越界；
     *         401 签发函数判定账号已停用/已到期或所属企业不可用；403 缺少权限；
     *         404 账号不存在；409 违反到期或重叠窗口约束、凭据唯一冲突
     */
    ServiceTokenIssuedVO issueToken(CurrentSession actor, String serviceAccountId, CreateServiceTokenDTO req);

    /**
     * 吊销一枚凭据（幂等）。
     *
     * <p>只把状态为 active 的行改为 revoked 并写入吊销时刻；不校验凭据是否存在，
     * 因此重复调用与吊销未知标识都同样成功。服务凭据不经会话存储缓存，
     * 吊销在下次核验时即时生效。
     *
     * @param actor        当前会话快照；须持有 {@code platform:service:write}
     * @param credentialId 凭据标识，须匹配 {@code sak_} 加 32 位小写十六进制，否则 400
     * @throws com.airagent.iam.web.error.ApiException 400 标识格式不合法；403 缺少权限
     */
    void revokeToken(CurrentSession actor, String credentialId);

    /**
     * keyset 分页拉取服务账号列表。
     *
     * @param actor     当前会话快照；须持有 {@code platform:service:write}
     * @param tenantIdRaw 可选企业过滤（UUID 文本）；{@code null} 或空白表示不过滤，
     *                    非 UUID 返回 400；企业不存在只得到空页而非 404
     * @param limitRaw  单页条数；{@code null} 取默认 20，合法范围 1..200，越界返回 400
     * @param cursorRaw 不透明游标（上一页末行 id 的 base64url 编码）；{@code null} 或空白表示首页，
     *                   解码后非 UUID 返回 400
     * @return 当前页 {@link PageVO}，按 id 升序；无匹配时 {@code items} 为空列表，
     *         无后续数据时 {@code nextCursor} 为 {@code null}
     * @throws com.airagent.iam.web.error.ApiException 400 参数不合法；403 缺少权限
     */
    PageVO<ServiceAccountVO> list(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);

    /**
     * 查询服务账号详情（含凭据元数据列表）。
     *
     * @param actor 当前会话快照；须持有 {@code platform:service:write}
     * @param idRaw 服务账号 UUID 文本；{@code null} 或非 UUID 返回 400
     * @return 账号视图与凭据元数据列表（签发时间倒序，可能为空列表），均不含摘要与明文
     * @throws com.airagent.iam.web.error.ApiException 400 id 不合法；403 缺少权限；
     *         404 账号不存在或不可见
     */
    ServiceAccountDetailVO get(CurrentSession actor, String idRaw);

    /**
     * 停用或重新启用服务账号。
     *
     * <p>停用即时生效于凭据核验（每次主库读取，无正向缓存），不删除既有凭据；
     * 每次成功调用把账号 {@code revision} +1。本方法不接受乐观并发基线。
     *
     * @param actor 当前会话快照；须持有 {@code platform:service:write}
     * @param idRaw 服务账号 UUID 文本；{@code null} 或非 UUID 返回 400
     * @param req   状态请求；{@code null}、{@code status} 为 {@code null} 或取值非
     *              {@code active}/{@code disabled} 时返回 400
     * @return 变更后的账号视图
     * @throws com.airagent.iam.web.error.ApiException 400 id 或 status 不合法；403 缺少权限；
     *         404 账号不存在（更新影响行数为 0）
     */
    ServiceAccountVO updateStatus(CurrentSession actor, String idRaw, UpdateServiceAccountDTO req);
}
