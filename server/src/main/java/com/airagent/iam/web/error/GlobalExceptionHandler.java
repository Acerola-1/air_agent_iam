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
 * 统一异常到错误信封。依赖类异常一律 503 失败关闭；不向响应泄露 SQL/连接细节。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ErrorEnvelope> handleApi(ApiException ex) {
        return ResponseEntity.status(ex.status())
                .body(ErrorEnvelope.of(ex.code(), ex.getMessage(), MDC.get("request_id")));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<ErrorEnvelope> handleBadRequest(Exception ex) {
        return ResponseEntity.badRequest()
                .body(ErrorEnvelope.of("bad_request", "请求体格式不合法", MDC.get("request_id")));
    }

    @ExceptionHandler(NotLoginException.class)
    ResponseEntity<ErrorEnvelope> handleNotLogin(NotLoginException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorEnvelope.of("unauthenticated", "未认证或会话已失效", MDC.get("request_id")));
    }

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

    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    ResponseEntity<ErrorEnvelope> handleNotFound(Exception ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorEnvelope.of("not_found", "资源不存在", MDC.get("request_id")));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ErrorEnvelope> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ErrorEnvelope.of("method_not_allowed", "请求方法不支持", MDC.get("request_id")));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorEnvelope> handleOther(Exception ex) {
        LOGGER.error("未处理异常 requestId={}", MDC.get("request_id"), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorEnvelope.of("conflict", "服务内部错误", MDC.get("request_id")));
    }

}
