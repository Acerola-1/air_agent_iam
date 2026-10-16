package com.airagent.iam.web.error;

import cn.dev33.satoken.exception.NotLoginException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * 全局异常 → 统一错误信封（{@link ErrorEnvelope}）的RestControllerAdvice。
 *
 * <p>原则：依赖类异常一律 503 失败关闭；未识别 SQLSTATE 落 500 且只打服务端日志，
 * 不向响应泄露 SQL/连接细节；每个信封都带 MDC 中的 request_id。
 * 服务层自行抛出的 {@link ApiException} 走第一个处理器，状态码与错误码原样透传。
 *
 * @author Acerola
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 服务端日志器（错误响应不外泄）。 */
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * 业务/协议异常：按异常自带状态与码返回。
     *
     * @param ex 服务层或拦截器抛出的 {@link ApiException}
     * @return 对应状态码的错误信封
     */
    @ExceptionHandler(ApiException.class)
    ResponseEntity<ErrorEnvelope> handleApi(ApiException ex) {
        return ResponseEntity.status(ex.status())
                .body(ErrorEnvelope.of(ex.code(), ex.getMessage(), MDC.get("request_id")));
    }

    /**
     * JSON 反序列化失败或参数类型不符：统一 400，不回显原始请求体。
     *
     * @param ex Spring MVC 绑定异常
     * @return 400 错误信封
     */
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<ErrorEnvelope> handleBadRequest(Exception ex) {
        return ResponseEntity.badRequest()
                .body(ErrorEnvelope.of("bad_request", "请求体格式不合法", MDC.get("request_id")));
    }

    /**
     * Sa-Token 未登录异常（理论上被拦截器先行覆盖，兜底保留）：401。
     *
     * @param ex NotLoginException
     * @return 401 错误信封
     */
    @ExceptionHandler(NotLoginException.class)
    ResponseEntity<ErrorEnvelope> handleNotLogin(NotLoginException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorEnvelope.of("unauthenticated", "未认证或会话已失效", MDC.get("request_id")));
    }

    /**
     * Redis/JDBC 连接失败与查询超时：503 失败关闭（身份数据宁拒不放）。
     *
     * @param ex 依赖类异常
     * @return 503 错误信封，服务端记 WARN
     */
    @ExceptionHandler({
            RedisConnectionFailureException.class,
            org.springframework.data.redis.RedisSystemException.class,
            CannotGetJdbcConnectionException.class,
            org.springframework.dao.QueryTimeoutException.class
    })
    ResponseEntity<ErrorEnvelope> handleDependencyDown(Exception ex) {
        LOGGER.warn("依赖不可用，失败关闭 type={} requestId={}", ex.getClass().getSimpleName(),
                MDC.get("request_id"));
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(ErrorEnvelope.of("dependency_unavailable", "身份依赖暂不可用",
                        MDC.get("request_id")));
    }

    /**
     * 未被服务层翻译的 DataAccessException：经 {@link PgErrorTranslator} 映射；
     * 落入未分类（500）时额外记 ERROR 附 SQLSTATE 与堆栈。
     *
     * @param ex Spring 数据访问异常
     * @return 映射后的错误信封
     */
    @ExceptionHandler(org.springframework.dao.DataAccessException.class)
    ResponseEntity<ErrorEnvelope> handleSql(org.springframework.dao.DataAccessException ex) {
        ApiException translated = PgErrorTranslator.toApiException(ex);
        if (translated.status() == 500) {
            String state = PgErrorTranslator.deepest(ex) == null
                    ? null : PgErrorTranslator.deepest(ex).getSQLState();
            LOGGER.error("未分类 SQL 异常 state={} requestId={}", state, MDC.get("request_id"), ex);
        }
        return ResponseEntity.status(translated.status())
                .body(ErrorEnvelope.of(translated.code(), translated.getMessage(),
                        MDC.get("request_id")));
    }

    /**
     * 静态资源与处理器未命中：404（throwExceptionIfNoHandlerFound=true 配合）。
     *
     * @param ex 未找到异常
     * @return 404 错误信封
     */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    ResponseEntity<ErrorEnvelope> handleNotFound(Exception ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorEnvelope.of("not_found", "资源不存在", MDC.get("request_id")));
    }

    /**
     * 方法不支持（如 GET 路径 POST）：405。
     *
     * @param ex 方法不支持异常
     * @return 405 错误信封
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ErrorEnvelope> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ErrorEnvelope.of("method_not_allowed", "请求方法不支持", MDC.get("request_id")));
    }

    /**
     * 兜底：其余未处理异常记 ERROR 后返回 500。
     *
     * <p>注意：当前实现错误码固定为 {@code conflict} 而状态 500——码与状态不一致
     * 系现状行为，消费方应按 HTTP 状态为准（已记录为整改疑点，本次文档任务不修改）。
     *
     * @param ex 任意异常
     * @return 500 错误信封
     */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorEnvelope> handleOther(Exception ex) {
        LOGGER.error("未处理异常 requestId={}", MDC.get("request_id"), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorEnvelope.of("internal_error", "服务内部错误", MDC.get("request_id")));
    }

}
