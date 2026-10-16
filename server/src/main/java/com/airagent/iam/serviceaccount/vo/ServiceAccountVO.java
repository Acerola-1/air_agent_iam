package com.airagent.iam.serviceaccount.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 服务账号 HTTP 出参（VO，对外响应模型；不含任何凭据材料）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl}
 * 从 {@link com.airagent.iam.serviceaccount.entity.ServiceAccountDO} 装配，出现在列表、
 * 创建与状态变更三个响应中，并作为 {@link ServiceAccountDetailVO#account()} 的嵌套结构。
 *
 * <p>场景：管理后台的服务账号列表与详情头部。视图只描述账号主体，凭据本身另由
 * {@link ServiceTokenVO} 表达；两者都不含 {@code token_digest} 摘要或明文密钥
 * （请求角色对凭据表的摘要列本就无直读权限，明文也不入库）。
 *
 * <p>特例：创建响应不由数据库回读，而是用请求参数与固定值当场拼装，因此
 * {@code status} 恒为 {@code active}、{@code revision} 恒为 1，{@code permissions} 是
 * 消毒后去重的请求权限码列表（与随后详情读回的结果在同一事务下等价）。
 *
 * @param id         账号 UUID 文本（服务端生成，客户端只读）
 * @param account    服务账号标识，{@code sa-} 前缀，全库唯一，创建后不可改
 * @param name       显示名，非空且最长 128 字符
 * @param tenantId   所属企业 UUID 文本（账号归属的租户）
 * @param status     账号状态，取值 {@code active} / {@code disabled}；停用即时生效于凭据核验，
 *                   但不删除或改写已签发凭据
 * @param audiences  允许的受众码列表（按入参顺序去重）；可为空列表，表示不面向任何受众
 * @param expiresAt  账号到期时刻，UTC ISO-8601 文本（java.time 默认格式化，秒为 0 时省略该位，
 *                   故不保证定长）。到期后签发与核验都失败
 * @param revision   账号修订号，插入为 1，之后仅在状态变更时 +1。授予/回收权限与
 *                   签发/吊销凭据不推进它，因此它不表示授权内容已变化；当前写接口也不接受
 *                   它作为乐观并发基线
 * @param permissions 已授予的权限码（按码升序）。列表响应与详情响应都会逐账号查询装配，
 *                    未授予任何权限时为空列表
 * @author Acerola
 */
@Schema(description = "服务账号视图：账号主体元数据，不含凭据摘要与明文")
public record ServiceAccountVO(
        @Schema(description = "服务账号 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "服务账号标识，sa- 前缀且全库唯一，创建后不可修改",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String account,
        @Schema(description = "显示名，非空且最长 128 字符", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "所属企业 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String tenantId,
        @Schema(description = "账号状态；disabled 表示已停用，其凭据下次核验即返回 account_disabled",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "disabled"})
        String status,
        @Schema(description = "允许的受众码列表（保序去重）；空列表表示不面向任何受众",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> audiences,
        @Schema(description = "账号到期时间，UTC ISO-8601 文本（秒为 0 时省略该位）", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String expiresAt,
        @Schema(description = "账号修订号：插入为 1，仅状态变更时 +1；授予权限与签发凭据不改变它",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long revision,
        @Schema(description = "已授予的权限码（按码升序）；空列表表示未授予权限",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> permissions
) {
}
