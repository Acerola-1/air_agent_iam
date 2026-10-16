package com.airagent.iam.web.error;

import org.postgresql.util.PSQLException;
import org.springframework.jdbc.UncategorizedSQLException;

/**
 * iam_auth 会话/授权函数 RAISE 状态码到协议错误的统一翻译。
 * Web 层（@RestControllerAdvice）与服务层（程序化事务边界）共用，保证不经控制器时语义一致。
 */
public final class PgErrorTranslator {

    private PgErrorTranslator() {
    }

    public static ApiException toApiException(UncategorizedSQLException ex) {
        return fromState(deepest(ex) == null ? null : deepest(ex).getSQLState());
    }

    /**
     * 宽入口：Spring 会把 CHECK 违例(23514)包成 DataIntegrityViolationException、
     * 唯一冲突包成 DuplicateKeyException，均需经同一 SQLSTATE 映射，不能只认 Uncategorized。
     */
    public static ApiException toApiException(org.springframework.dao.DataAccessException ex) {
        PSQLException cause = deepest(ex);
        return fromState(cause == null ? null : cause.getSQLState());
    }

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

    public static String sqlStateOf(UncategorizedSQLException ex) {
        PSQLException cause = deepest(ex);
        return cause == null ? null : cause.getSQLState();
    }

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
