package com.airagent.iam.internal.service;

import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.security.internal.InternalClient;

/**
 * 运行时短票据业务（Service 接口层）。
 *
 * <p>分层位置：{@code /v1/internal/runtime-tickets} 的用例入口，实现见
 * {@link com.airagent.iam.internal.service.impl.RuntimeTicketServiceImpl}。签票不引入第二权威：
 * 主体有效性完全复用 {@link IntrospectionService#loadHumanSnapshot(String)} 的实时核验结果。
 *
 * <p>用途边界：票据是给运行时使用的<b>短入口凭据</b>，受众严格限定
 * {@link IntrospectionService#RUNTIME_AUDIENCE}，不得用于知识库或用户管理，也不得反过来
 * 当作 {@code subject_token} 再核验或再签票。原会话的有效期与撤销状态不受票据 60 秒
 * 上界影响——票据到期而会话仍有效时，重新核验即可再签。
 *
 * @author Acerola
 */
public interface RuntimeTicketService {

    /**
     * 实时核验人类会话后签发一张 rt-v1 票据。
     *
     * <p>顺序即语义：受众与客户端注册检查 → 主体实时核验（PG 权威 + Redis 存活）→
     * 企业上下文与 {@code target_tenant_id}/{@code expected_ctx_version} 一致性 → 有效期取小
     * → 签名 → 同事务写审计。任何一步不满足都失败关闭，绝不签出"降级"票据。
     *
     * <p>有效期：{@code min(60 秒, 会话 idle/absolute 最早到期时刻 - now)}；
     * 快照中三个到期字段都缺失时按远未过期的上界处理，实际仍受 60 秒钳制；
     * 剩余有效期不足（不高于签发时刻）时返回 403。
     *
     * @param client  已完成凭据核验的内部客户端，必须已注册 runtime 受众；不可为 {@code null}
     * @param request 签票请求；{@code null} 请求体返回 400
     * @return 签发的票据视图（含 {@code Bearer} 类型、UTC 到期文本与剩余秒数）
     * @throws com.airagent.iam.web.error.ApiException 400 必填项缺失或 UUID 不合法、受众非 runtime；
     *                      401 客户端凭据无效、会话不存在/已撤销/已过期、账号已停用；
     *                      403 客户端未注册 runtime 受众、企业上下文不可用（停用、成员关系缺失）、
     *                      会话未选择企业、会话剩余有效期不足；
     *                      409 目标企业或上下文代次与当前会话不一致；
     *                      503 签名密钥未配置或依赖不可用
     */
    RuntimeTicketVO issue(InternalClient client, RuntimeTicketDTO request);
}
