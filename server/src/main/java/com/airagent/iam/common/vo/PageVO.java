package com.airagent.iam.common.vo;

import java.util.List;

/**
 * 通用分页出参（VO）：keyset 游标分页的页载荷。
 *
 * <p>所有管理列表端点共用本形状；不含总数与页码——分页语义是"取游标之后的下 N 条"。
 *
 * @param items      当前页数据，恒为非 {@code null} 列表（可为空）
 * @param nextCursor 下一页不透明游标；{@code null} 表示已到末页，消费方原样回传即可
 * @param <T>        页内元素类型（各业务 VO）
 * @author Acerola
 */
public record PageVO<T>(List<T> items, String nextCursor) {
}
