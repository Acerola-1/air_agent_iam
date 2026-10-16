package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 服务账号（机器主体）身份视图（VO，内省令牌模式下的机器主体成功响应）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl} 在服务账号分支
 * 判定 {@code status = ok} 后装配，数据全部来自 {@code iam_auth.load_service_identity}
 * 的一次主库读取，不做跨请求缓存。
 *
 * <p>与人类视图的关键差异：机器主体<b>没有会话、没有企业成员关系、没有会话纪元</b>，
 * 因此 {@code user}、{@code session}、{@code membership} 与 {@code revisions} 恒为
 * {@code null}（契约上"整体不适用"，不是"暂时未知"）。它也不参与平台角色与平台管理标记
 * 的裁剪口径——平台管理员身份只在人类视图中按受众隐藏，机器视图本就不含该维度。
 *
 * <p>受众与权限：本视图只在请求受众出现于服务账号自身注册受众数组时产生（否则 403）；
 * {@code permissions} 为活跃且<b>非资源型</b>（{@code resource_code IS NULL}）的授予集合，
 * 资源边界由授予层触发器与消费方默认拒绝双重兜住，故此处出现某码不等于可访问具体资源。
 *
 * <p>{@code schemaVersion} 沿用 {@code iam.introspection.v1}（与 inactive 信封同一标识），
 * 而非人类身份视图的 {@code iam.identity.v1}；时间字段为数据库 timestamptz 序列化出的
 * ISO-8601 带偏移文本，{@code evaluatedAt} 为服务端评估时刻的 UTC 文本。
 *
 * @param schemaVersion        结构版本标识，固定 {@code iam.introspection.v1}
 * @param active               机器主体是否有效；本视图只在权威核验通过后装配，恒为 {@code true}
 * @param issuer               签发方标识（配置 {@code iam.issuer}），仅作路由与区分权威来源，不是可校验 URL
 * @param audience             本次核验声明的受众（已确认在服务账号注册受众内）
 * @param principal            主体三元组，{@code type = service_account}、{@code realm = service}
 * @param user                 人类账号信息；机器主体恒为 {@code null}
 * @param session              会话信息；机器主体恒为 {@code null}
 * @param membership           企业成员关系；机器主体恒为 {@code null}
 * @param currentTenant        服务账号归属企业；快照无企业节点时为 {@code null}
 * @param permissions          活跃且非资源型的权限码列表，顺序为数据库聚合顺序；无授予时为空列表
 * @param serviceAccountRevision 服务账号记录代次（建档为 1，状态类管理写操作 +1；不随权限授予推进）
 * @param credentialId         本次命中的凭据标识（轮换会引入新凭据 id）
 * @param credentialRevision   凭据修订号，同一账号内每次签发 +1，消费方据此识别被替换的旧凭据
 * @param credentialExpiresAt  凭据到期时刻（ISO-8601 文本）；节点缺失时为 {@code null}
 * @param overlapUntil         轮换重叠窗口截止时刻（ISO-8601 文本），上限为签发后 24 小时且不超过本凭据到期；
 *                             {@code null} 表示无重叠窗口，旧凭据即刻失效
 * @param revisions            四项权威修订；机器主体恒为 {@code null}
 * @param evaluatedAt          服务端装配本视图的时刻（UTC ISO-8601 文本）
 * @author Acerola
 */
@Schema(name = "ServiceIdentityVO", description = "服务账号（机器主体）实时身份：凭据代次与到期、注册受众下的非资源型权限码。"
        + "无会话与成员关系，故 user/session/membership/revisions 恒为 null")
public record ServiceIdentityVO(

        @Schema(description = "结构版本，固定 iam.introspection.v1", example = "iam.introspection.v1")
        String schemaVersion,

        @Schema(description = "主体是否有效；本视图只在权威核验通过后装配，恒为 true")
        boolean active,

        @Schema(description = "签发方标识（iam.issuer）", example = "air-agent-iam")
        String issuer,

        @Schema(description = "本次声明并已确认注册的受众", example = "knowledge")
        String audience,

        @Schema(description = "主体三元组（type/id/realm）")
        Principal principal,

        @Schema(description = "人类账号信息；机器主体恒为 null", nullable = true)
        Object user,

        @Schema(description = "会话信息；机器主体恒为 null", nullable = true)
        Object session,

        @Schema(description = "企业成员关系；机器主体恒为 null", nullable = true)
        Object membership,

        @Schema(description = "服务账号归属企业；无企业节点时为 null", nullable = true)
        Tenant currentTenant,

        @Schema(description = "活跃且非资源型的权限码集合；出现某码不等于可访问具体资源")
        java.util.List<String> permissions,

        @Schema(description = "服务账号记录代次（建档 1，状态类管理写操作 +1）", example = "1")
        long serviceAccountRevision,

        @Schema(description = "命中的凭据标识", example = "cred-2f6c81a0")
        String credentialId,

        @Schema(description = "凭据修订号，同一账号每次签发 +1", example = "2")
        long credentialRevision,

        @Schema(description = "凭据到期时刻（ISO-8601 文本），缺失时为 null",
                nullable = true, example = "2027-01-15T00:00:00Z")
        String credentialExpiresAt,

        @Schema(description = "轮换重叠窗口截止时刻（ISO-8601 文本，上限为签发后 24 小时）；"
                + "null 表示无重叠窗口", nullable = true, example = "2026-10-17T02:11:00Z")
        String overlapUntil,

        @Schema(description = "四项权威修订；机器主体不适用，恒为 null", nullable = true)
        RevisionsDTO revisions,

        @Schema(description = "服务端评估时刻（UTC ISO-8601 文本）", example = "2026-10-16T02:11:00Z")
        String evaluatedAt
) {

    /**
     * 主体三元组（VO 内嵌结构）。
     *
     * @param type  主体类型，服务账号恒为 {@code service_account}（人类视图用 {@code human}）
     * @param id    主体 id（UUID 文本）
     * @param realm 主体所属域，服务账号为 {@code service}（人类为 {@code workforce}，
     *              内部客户端为 {@code internal_client}）
     */
    @Schema(description = "主体标识三元组")
    public record Principal(String type, String id, String realm) {
    }

    /**
     * 企业摘要（VO 内嵌结构），仅给出消费方做映射所需的最小字段。
     *
     * @param id     企业 id（UUID 文本）
     * @param code   企业编码（对外可读的稳定标识）
     * @param name   企业显示名
     * @param status 企业状态；能在本视图出现即为 {@code active}（非活跃企业已被判失效）
     */
    @Schema(description = "服务账号归属企业摘要")
    public record Tenant(String id, String code, String name, String status) {
    }
}
