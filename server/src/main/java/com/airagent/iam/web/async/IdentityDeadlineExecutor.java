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

/**
 * 内部实时核验的有界异步执行器（Web 层组件）。
 *
 * <p>从请求进入过滤器的时刻起算 500ms 端到端上界，本执行器占用其中 450ms
 * 业务预算（预留约 50ms 给异步派发与响应写回）。任务提交到虚拟线程执行，
 * 同时在途任务数经信号量限为 64：预算已耗尽或槽位满时立即以 503 失败关闭，
 * 不排队等待。定时闹钟线程负责到点未完成的调用置 503 并中断后台任务；
 * MDC（request_id）随任务迁移，完成后清理。
 *
 * <p>注意：该预算是已实现机制；压力下 P50/P95 端到端指标未达原验收目标，
 * 见 docs/reviews/iam-remediation-validation.md，不得据本类注释宣称性能保证。
 *
 * @author Acerola
 */
@Component
public class IdentityDeadlineExecutor {

    // 500ms 端到端上界预留 50ms 给异步派发与响应写回。
    /** 业务预算毫秒（500ms 端到端预留 50ms 派发）。 */
    private static final long TIMEOUT_MILLIS = 450;
    /** 同时在途核验任务上限。 */
    private static final int MAX_IN_FLIGHT = 64;
    /** 核验任务虚拟线程执行器。 */
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    /** 单线程 daemon 闹钟：到点未完成即置 503 并中断后台任务。 */
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("iam-identity-deadlines").factory());
    /** 在途容量信号量（满即 503 不排队）。 */
    private final Semaphore capacity = new Semaphore(MAX_IN_FLIGHT);

    /**
     * 在剩余预算内异步执行核验操作并返回 DeferredResult。
     *
     * <p>失败关闭语义：剩余预算 {@code <= 0} 或在途数达上限时不执行 operation，
     * 直接 503；执行中抛出的异常作为错误结果传播（由全局异常处理器映射）。
     *
     * @param requestStartedNanos 请求进入时的单调纳秒时刻（RequestIdFilter 属性）
     * @param operation           待执行的核验操作（其返回值作为成功结果写出）
     * @param <T>                 结果类型
     * @return 异步结果句柄；超时/过载为 503 ApiException 错误结果
     */
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

    /**
     * 构造失败关闭的 503 异常（超时与过载共用文案）。
     *
     * @return {@code dependency_unavailable} 的 {@link ApiException}
     */
    private ApiException unavailable() {
        return ApiException.dependencyUnavailable("身份核验暂不可用，请稍后重试");
    }

    /**
     * 容器停止时立即中断在途核验与闹钟调度。
     */
    @PreDestroy
    public void close() {
        executor.shutdownNow();
        deadlines.shutdownNow();
    }
}
