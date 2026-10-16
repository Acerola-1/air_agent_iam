package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 平台账号 HTTP 出参（VO，对外响应模型；不含口令摘要）。
 *
 * <p>账号列经过裁剪：请求角色 iam_app 对 {@code iam.users.password_hash} 无读取权限，
 * 因此任何管理查询都无法带出口令信息。除平台账号接口外，本视图也作为
 * {@link MemberVO#user()} 的嵌套结构出现在企业成员响应中。
 *
 * @param id           账号 UUID 文本（主键，服务端生成，客户端只读）
 * @param realm        账号域；当前账号管理创建的均为 {@code workforce}，(realm, account) 全库唯一
 * @param account      登录账号，可打印 ASCII 3..64 字符，同 realm 下唯一
 * @param displayName  显示名，非空且最长 128 字符
 * @param status       账号状态，仅 {@code active} / {@code disabled}；停用即失去登录能力与活跃会话
 * @param authRevision 用户授权代次（从 0 起单调递增）。口令或状态变更、平台角色增删、
 *                     会话撤销都会推进它；会话权威快照以此判定既有会话的授权是否已过期，
 *                     也是管理端 PATCH 的乐观并发基线（expected_revision）
 * @param platformRoles 账号当前持有的平台角色码（按码升序）。平台账号接口返回真实集合，
 *                     可能为空列表；企业成员视图中的嵌套账号恒为空列表（不查询平台角色）
 * @param createdAt    账号创建时间，UTC ISO-8601 文本（由 java.time 默认格式化生成，
 *                     秒为 0 时该位会被省略，故不保证定长）
 * @author Acerola
 */
@Schema(description = "平台账号视图（不含口令摘要）")
public record UserVO(
        @Schema(description = "账号 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "账号域，管理面创建的均为 workforce", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"workforce"})
        String realm,
        @Schema(description = "登录账号，可打印 ASCII 3..64 字符", requiredMode = Schema.RequiredMode.REQUIRED)
        String account,
        @Schema(description = "显示名，非空且最长 128 字符", requiredMode = Schema.RequiredMode.REQUIRED)
        String displayName,
        @Schema(description = "账号状态；disabled 表示已停用并撤销全部会话", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"active", "disabled"})
        String status,
        @Schema(description = "用户授权代次，单调递增；PATCH 可作为 expected_revision 基线回传",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long authRevision,
        @Schema(description = "平台角色码（按码升序）；企业成员嵌套视图中恒为空列表",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> platformRoles,
        @Schema(description = "创建时间，UTC ISO-8601 文本（秒为 0 时省略该位）", format = "date-time",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String createdAt
) {
}
