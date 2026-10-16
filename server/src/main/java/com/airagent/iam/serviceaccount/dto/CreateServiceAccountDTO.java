package com.airagent.iam.serviceaccount.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 服务账号建档请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：平台管理员为某个企业登记一个机器身份（服务账号），并预先声明它可面向的受众
 * 与可持有的企业域权限码；由
 * {@link com.airagent.iam.serviceaccount.controller.ServiceAccountAdminController#create}
 * 接收（{@code POST /v1/admin/service-accounts} 与 {@code /web-api} 同名路径），交给
 * {@link com.airagent.iam.serviceaccount.service.ServiceAccountService#create} 裁决
 * {@code platform:service:write} 并开启事务。
 *
 * <p>本请求只建账号主体，<b>不产生任何凭据</b>：明文密钥只在
 * {@link com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO} 对应的签发响应里出现一次，
 * 因此本 DTO 不携带任何秘密字段，默认的 record {@code toString()} 不会泄露敏感值。
 * 本类无校验注解，格式判定全在服务层（不合法一律 400）；请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省返回 400。
 * 字段名按全局 SNAKE_CASE 解析（account / name / tenant_id / audiences /
 * expires_in_days / permissions）。
 *
 * @param account       服务账号标识，必须匹配 {@code sa-[a-z0-9][a-z0-9-]{1,62}[a-z0-9]}
 *                      （即 {@code sa-} 前缀、总长 6..66、首尾为小写字母数字、中间允许连字符），
 *                      全库唯一
 * @param name          显示名，非空白且不超过 128 字符
 * @param tenantId      所属企业 UUID 文本；企业必须存在且状态为 {@code active}
 * @param audiences     允许核验的受众码列表；{@code null} 视为空列表，元素去重且保序，
 *                      单元素须匹配 {@code [a-z0-9][a-z0-9.:-]{0,63}}
 * @param expiresInDays 账号有效期天数；{@code null} 取默认 90，合法范围 1..365（含），
 *                      数据库另有硬顶：到期时刻不得晚于写入时刻加 365 天
 * @param permissions   要授予的权限码列表；{@code null} 视为空列表，消毒规则同 audiences，
 *                      只接受企业域（{@code scope='tenant'}）、非资源型且已启用的权限码，
 *                      任一越界整体 400
 * @author Acerola
 */
@Schema(description = "服务账号建档请求。只创建账号主体与权限声明，不返回凭据；"
        + "凭据需另行调用签发接口，明文密钥仅在该响应中出现一次")
public record CreateServiceAccountDTO(

        @Schema(description = "服务账号标识：正则 sa-[a-z0-9][a-z0-9-]{1,62}[a-z0-9]，"
                + "即 sa- 前缀、总长 6..66 字符、首尾为小写字母数字、中间可含连字符。全库唯一，"
                + "重复返回 409。", requiredMode = Schema.RequiredMode.REQUIRED, example = "sa-batch-report")
        String account,

        @Schema(description = "显示名：非空白且不超过 128 字符，服务层裁决。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "夜间报表任务")
        String name,

        @Schema(description = "所属企业 UUID：账号归属的租户，企业须处于 active 状态，"
                + "否则返回 400（不区分不存在与已停用）。", format = "uuid",
                requiredMode = Schema.RequiredMode.REQUIRED,
                example = "01930000-0000-4000-8000-000000000001")
        String tenantId,

        @Schema(description = "受众码列表：每个元素匹配 [a-z0-9][a-z0-9.:-]{0,63}（最长 64 字符），"
                + "空白、含非法字符或超长元素返回 400；重复元素按出现顺序去重。省略或 null 为空列表。"
                + "核验时要求被核验令牌声明的受众在此列表内。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> audiences,

        @Schema(description = "有效期天数：整数 1..365（含两端），缺省 90；越界返回 400。"
                + "数据库另有 expires_at 不得超过建档时刻 +365 天的硬顶约束。"
                + "到期后凭据核验判定账号已到期，签发接口不再可用。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "90")
        Integer expiresInDays,

        @Schema(description = "授予的权限码：字符规则同 audiences。只接受 scope 为 tenant、"
                + "resource_code 为空且 status 为 active 的权限；含平台专属、资源型、未知或停用权限码时整体 400"
                + "（不部分生效）。省略或空数组表示建档时不授予任何权限。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> permissions
) {
}
