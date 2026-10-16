package com.airagent.iam.audit.dto;

import com.airagent.iam.web.error.ApiException;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 审计日志查询入参（DTO，Controller → Service）。
 *
 * <p>场景：{@link com.airagent.iam.audit.controller.AuditController#list} 把查询串里的
 * 三个可选参数装配成本记录，交给
 * {@link com.airagent.iam.audit.service.AuditService#list}。三个参数都允许缺省，
 * {@code null} 一律表示"未提供，取默认或不作该维度过滤"。注意空白值的口径并不相同：
 * {@code cursor} 为空白串时按首页处理，而 {@code action} 传空串会原样成为空 LIKE 模式
 * （匹配不到任何行）。本记录对任何字段都不做改写或归一化，界限之外的值一律原样透传给服务层。
 *
 * <p>校验位置刻意放在紧凑构造器：非 HTTP 调用方（内部脚本、测试）复用本记录时受同样的界限约束，
 * 越界即在构造瞬间抛 {@link ApiException}（400），早于权限裁决与任何 SQL。
 * 上界 200 与管理线 {@code AdminSupport.MAX_LIMIT} 同值，服务层的
 * {@code clampLimit} 会对同一区间二次核对（缺省值 20 由服务层给出，本记录不做归一）。
 *
 * <p>本记录不是响应体：字段以 Java 名直接传给服务层，不经过 JSON 序列化；
 * 出参形状见 {@link com.airagent.iam.audit.vo.AuditLogVO}。
 *
 * @param limit  单页条数，1..200（含边界）；{@code null} 表示未提供
 * @param cursor 上一页返回的不透明游标（base64url 文本），最长 64 字符；{@code null} 表示首页
 * @param action 动作码的 SQL LIKE 过滤模式，最长 128 字符；{@code null} 表示不按动作过滤
 * @author Acerola
 */
@Schema(description = "审计日志查询参数（三项均可缺省）。不接受租户归属参数——"
        + "可见范围完全由会话权限码与 PostgreSQL RLS 决定")
public record AuditLogQueryDTO(

        @Schema(description = "单页条数：1..200（含边界），缺省 20。越界直接 400，不静默截断，"
                + "服务端也不会返回超宽页。", minimum = "1", maximum = "200", example = "50")
        Integer limit,

        @Schema(description = "上一页 next_cursor 原样回传：本页最后一行审计 id 十进制文本的 "
                + "base64url（无填充）编码，最长 64 字符。首页省略；无法解码或解析结果不大于 0 返回 400。"
                + "游标不承载排序方向，翻页顺序固定为 id 降序。", maxLength = 64, example = "MTIzNDU2")
        String cursor,

        @Schema(description = "动作码过滤：SQL LIKE 模式，最长 128 字符，大小写敏感，"
                + "其中 * 由服务层转为多字符通配符（如 admin.user.* 匹配该前缀的全部动作）。"
                + "直接写百分号或下划线同样按通配生效，未做额外转义；省略该参数才是不过滤，"
                + "传空串会作为空模式匹配不到任何行。示例 admin.user.create 为精确匹配。",
                maxLength = 128, example = "auth.*")
        String action) {

    /** 单页条数上界，与管理线分页上限（200）对齐；超过即 400。 */
    private static final int MAX_PAGE_SIZE = 200;
    /** 游标文本长度上界；正常游标是页宽至多 200 的 bigint id 的 base64url，远短于此。 */
    private static final int MAX_CURSOR_LENGTH = 64;
    /**
     * 动作码模式长度上界。数据库 {@code audit_logs.action} 是无长度约束的 text 列，
     * 本上界纯粹是查询入参的输入防护，避免超长模式串进入 LIKE 匹配。
     */
    private static final int MAX_ACTION_LENGTH = 128;

    /**
     * 紧凑构造器：对三个可选参数做界限校验，不改写、不归一任何值。
     *
     * @param limit  单页条数；非 {@code null} 时必须落在 1..200，
     *               {@code null} 由服务层取默认 20
     * @param cursor 游标原文；非 {@code null} 时长度不得超过 64；
     *               空白串在此视为合法（由服务层按首页处理）
     * @param action 动作码 LIKE 模式；非 {@code null} 时长度不得超过 128
     * @throws ApiException 400 当任一参数越界（消息只说明字段与界限，不含内部细节）
     */
    public AuditLogQueryDTO {
        if (limit != null && (limit < 1 || limit > MAX_PAGE_SIZE)) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        if (cursor != null && cursor.length() > MAX_CURSOR_LENGTH) {
            throw ApiException.badRequest("cursor 不合法");
        }
        if (action != null && action.length() > MAX_ACTION_LENGTH) {
            throw ApiException.badRequest("action 不能超过 128 个字符");
        }
    }
}
