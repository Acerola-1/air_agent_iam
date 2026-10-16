package com.airagent.iam.web.async;

import com.airagent.iam.web.error.ApiException;
import jakarta.annotation.PreDestroy;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.async.DeferredResult;

/** 内部实时核验总预算包含客户端认证；超时响应失败关闭，后台工作数量有界。 */
@Component
public class IdentityDeadlineExecutor {

    // 500ms 端到端上界预留 50ms 给异步派发与响应写回。
    private static final long TIMEOUT_MILLIS = 450;
    private static final int MAX_IN_FLIGHT = 64;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("iam-identity-deadlines").factory());
    private final Semaphore capacity = new Semaphore(MAX_IN_FLIGHT);

    public <T> DeferredResult<T> execute(long requestStartedNanos, Supplier<T> operation) {
        long remaining = TIMEOUT_MILLIS
                - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - requestStartedNanos);
        DeferredResult<T> result = new DeferredResult<>(Math.max(1, remaining));
        if (remaining <= 0 || !capacity.tryAcquire()) {
            result.setErrorResult(unavailable());
            return result;
        }
        Map<String, String> context = MDC.getCopyOfContextMap();
        var future = executor.submit(() -> {
            if (context != null) {
                MDC.setContextMap(context);
            }
            try {
                result.setResult(operation.get());
            } catch (Exception ex) {
                result.setErrorResult(ex);
            } finally {
                capacity.release();
                MDC.clear();
            }
        });
        long delay = Math.max(0, TIMEOUT_MILLIS
                - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - requestStartedNanos));
        var alarm = deadlines.schedule(() -> {
            if (result.setErrorResult(unavailable())) {
                future.cancel(true);
            }
        }, delay, TimeUnit.MILLISECONDS);
        result.onTimeout(() -> {
            result.setErrorResult(unavailable());
            future.cancel(true);
        });
        result.onCompletion(() -> {
            alarm.cancel(false);
            future.cancel(true);
        });
        return result;
    }

    private ApiException unavailable() {
        return ApiException.dependencyUnavailable("身份核验暂不可用，请稍后重试");
    }

    @PreDestroy
    public void close() {
        executor.shutdownNow();
        deadlines.shutdownNow();
    }
}
