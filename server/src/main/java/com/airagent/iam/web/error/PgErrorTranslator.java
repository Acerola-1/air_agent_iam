package com.airagent.iam.web.error;

import org.postgresql.util.PSQLException;
import org.springframework.jdbc.UncategorizedSQLException;

/**
 * iam_auth 会话/授权函数 RAISE 状态码到协议错误的统一翻译（Web 层组件，全静态方法）。
 *
 * <p>Web 层（GlobalExceptionHandler）与服务层（程序化事务边界 catch）共用，
 * 保证同一 SQLSTATE 无论经控制器还是被服务内部捕获，HTTP 语义一致。
 * 未识别状态一律 500，且响应文本不泄露 SQL 与连接细节。
 *
 * @author Acerola
 */
public final class PgErrorTranslator {

    /** 工具类禁止实例化。 */
    private PgErrorTranslator() {
    }

    /**
     * 翻译未分类 SQL 异常。
     *
     * @param ex Spring 包装的 UncategorizedSQLException
     * @return 按 SQLSTATE 映射的 {@link ApiException}；cause 链中无 PSQLException 时按 500
     */
    public static ApiException toApiException(UncategorizedSQLException ex) {
        return fromState(deepest(ex) == null ? null : deepest(ex).getSQLState());
    }

    /**
     * 宽入口：Spring 会把 CHECK 违例(23514)包成 DataIntegrityViolationException、
     * 唯一冲突包成 DuplicateKeyException，均需经同一 SQLSTATE 映射，不能只认 Uncategorized。
     *
     * @param ex 任意 Spring DataAccessException
     * @return 映射结果：连接/超时/锁类（08*、57P01/2/3、57014、55P03）→503；
     *         P0010→409 context_changed；P0012→403；23514/40001/40P01/23505→409；
     *         28P01/28000→401；42501→403；其余→500
     */
    public static ApiException toApiException(org.springframework.dao.DataAccessException ex) {
        PSQLException cause = deepest(ex);
        return fromState(cause == null ? null : cause.getSQLState());
    }

    /**
     * SQLSTATE → 协议错误映射（唯一事实来源）。
     *
     * @param state PostgreSQL SQLSTATE；{@code null} 按未识别处理
     * @return 对应 {@link ApiException}
     */
    private static ApiException fromState(String state) {
        if (state != null && (state.startsWith("08") || state.equals("57P01") || state.equals("57P02")
                || state.equals("57P03") || state.equals("57014") || state.equals("55P03"))) {
            return ApiException.dependencyUnavailable("身份依赖暂不可用");
        }
        return switch (state == null ? "" : state) {
            case "P0010" -> new ApiException(409, "context_changed", "上下文版本已变化，请刷新后重试");
            case "P0012" -> new ApiException(403, "forbidden", "目标企业不可用或成员关系无效");
            case "23514" -> new ApiException(409, "conflict", "操作违反业务约束（如最后管理员保护/层级成环/可授边界）");
            case "40001", "40P01" -> new ApiException(409, "conflict", "并发修改冲突，请重试");
            case "23505" -> new ApiException(409, "conflict", "资源已存在或发生唯一冲突");
            case "28P01", "28000" ->
                    new ApiException(401, "unauthenticated", "会话无效、已撤销或已过期");
            case "42501" -> new ApiException(403, "forbidden", "无权执行该操作");
            default -> new ApiException(500, "internal_error", "服务内部错误");
        };
    }

    /**
     * 仅取 SQLSTATE，不做映射（日志/分支判断用）。
     *
     * @param ex 未分类 SQL 异常
     * @return SQLSTATE；cause 链无 PSQLException 时 {@code null}
     */
    public static String sqlStateOf(UncategorizedSQLException ex) {
        PSQLException cause = deepest(ex);
        return cause == null ? null : cause.getSQLState();
    }

    /**
     * 沿 cause 链找最深（最原始）的 PSQLException。
     *
     * @param throwable 任意异常，可为 {@code null}
     * @return 最内层 {@link PSQLException}；不存在时 {@code null}
     */
    public static PSQLException deepest(Throwable throwable) {
        Throwable cur = throwable;
        PSQLException found = null;
        while (cur != null) {
            if (cur instanceof PSQLException psql) {
                found = psql;
            }
            cur = cur.getCause();
        }
        return found;
    }
}
