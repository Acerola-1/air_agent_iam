package com.airagent.iam.serviceaccount.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 服务账号详情 HTTP 出参（VO，账号主体 + 凭据元数据列表）。
 *
 * <p>分层：由 {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl#get}
 * 装配——先按 id 读取账号视图（不存在即 404），再经受控函数
 * {@code iam_auth.list_service_tokens} 取该账号的全部凭据元数据并列在一起返回。
 *
 * <p>场景：管理后台的服务账号详情页。凭据历史与账号主体一次给全，避免前端为每一枚凭据
 * 再发请求；列表接口不返回本结构（不含凭据）。
 *
 * <p>凭据边界：本结构只包含可公开展示的凭据标识与时间/状态列，既没有明文密钥也没有
 * {@code token_digest} 摘要。明文密钥只存在于签发响应
 * {@link ServiceTokenIssuedVO} 中且仅出现一次，无法经本接口或任何其他接口回取。
 *
 * @param account 账号主体视图（同列表/创建响应中的结构）
 * @param tokens  该账号的凭据元数据列表，按签发时间倒序、同刻按凭据标识升序；从未签发时为空列表，
 *                不会为 {@code null}。包含已吊销与已过期的历史行，便于审计轮换结果
 * @author Acerola
 */
@Schema(description = "服务账号详情：账号视图与凭据元数据列表；不含凭据摘要与明文")
public record ServiceAccountDetailVO(
        @Schema(description = "账号主体元数据", requiredMode = Schema.RequiredMode.REQUIRED)
        ServiceAccountVO account,

        @Schema(description = "凭据元数据列表（签发时间倒序）；空列表表示从未签发。"
                + "每项只含标识、代次、状态与时间列", requiredMode = Schema.RequiredMode.REQUIRED)
        java.util.List<ServiceTokenVO> tokens
) {
}
