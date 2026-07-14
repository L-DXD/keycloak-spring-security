package com.ids.keycloak.security.ratelimit;

import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import lombok.extern.slf4j.Slf4j;

/**
 * {@link ConcurrentHashMap} 기반 인메모리 Rate Limiter 구현체입니다.
 * <p>
 * Sliding Window Counter 알고리즘을 사용하여 인증 실패를 제한합니다.
 * 윈도우 시간 내에 {@code maxRequests}를 초과하면 {@code blockDurationSeconds} 동안 차단합니다.
 * </p>
 * <p>
 * 브루트포스 방지 목적이므로 인증 실패 시에만 카운트하며,
 * 인증 성공 요청은 카운트에 영향을 주지 않습니다.
 * </p>
 * <p>
 * 주기적으로 만료된 엔트리를 정리하여 메모리 누수를 방지합니다.
 * </p>
 * <p>
 * <b>용량 상한 정책(CWE-400 방어):</b> {@code maxTrackedKeys}로 동시 추적 가능한 키 수를 제한합니다.
 * 맵이 상한에 도달한 상태에서 아직 추적되지 않은 새 키가 유입되면 <b>fail-closed</b>로
 * 즉시 차단 처리합니다(카디널리티 공격으로 인한 메모리 무한 증가를 방지하기 위해,
 * 알려지지 않은 새 키를 추적 실패 시 통과시키는 fail-open 대신 차단을 택함).
 * 이미 추적 중인 키는 상한과 무관하게 정상적으로 판단됩니다.
 * </p>
 */
@Slf4j
public class InMemoryRateLimiter implements RateLimiter {

    /** {@code maxTrackedKeys}를 지정하지 않는 하위 호환 생성자의 기본 상한. */
    private static final int DEFAULT_MAX_TRACKED_KEYS = 100_000;

    /** 용량 상한 도달 경고 로그를 요약해서 남기는 주기(밀리초). 로그 폭주(2차 DoS) 방지용. */
    private static final long CAPACITY_WARN_LOG_INTERVAL_MS = 60_000L;

    private final int maxRequests;
    private final long windowSeconds;
    private final long blockDurationSeconds;
    private final int maxTrackedKeys;

    private final Map<String, SlidingWindowCounter> counters = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor;

    /** 용량 상한으로 인한 누적 차단(신규 키 거부) 횟수. 외부 메트릭 수집용으로 노출. */
    private final AtomicLong capacityRejectionCount = new AtomicLong(0);
    /** 마지막 요약 로그 이후 발생한 용량 상한 차단 횟수. */
    private final AtomicLong intervalRejectionCount = new AtomicLong(0);
    /** 마지막으로 용량 상한 경고 로그를 남긴 시각(epoch millis). */
    private final AtomicLong lastCapacityWarnLogEpochMs = new AtomicLong(0);

    public InMemoryRateLimiter(int maxRequests, long windowSeconds, long blockDurationSeconds) {
        this(maxRequests, windowSeconds, blockDurationSeconds, DEFAULT_MAX_TRACKED_KEYS);
    }

    public InMemoryRateLimiter(int maxRequests, long windowSeconds, long blockDurationSeconds,
                                int maxTrackedKeys) {
        this.maxRequests = maxRequests;
        this.windowSeconds = windowSeconds;
        this.blockDurationSeconds = blockDurationSeconds > 0 ? blockDurationSeconds : windowSeconds;
        this.maxTrackedKeys = maxTrackedKeys > 0 ? maxTrackedKeys : DEFAULT_MAX_TRACKED_KEYS;

        // 만료된 엔트리 정리 스케줄러 (5분마다)
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "rate-limit-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        this.cleanupExecutor.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.MINUTES);
    }

    @Override
    public boolean isBlocked(String key) {
        SlidingWindowCounter counter = counters.get(key);
        if (counter == null) {
            // 아직 추적되지 않은 키. 용량이 이미 상한이면 fail-closed로 차단.
            if (counters.size() >= maxTrackedKeys) {
                recordCapacitySaturated();
                return true;
            }
            return false;
        }
        return counter.isBlocked(Instant.now());
    }

    @Override
    public void recordFailure(String key) {
        Instant now = Instant.now();
        SlidingWindowCounter counter = counters.compute(key, (k, existing) -> {
            if (existing != null) {
                return existing;
            }
            if (counters.size() >= maxTrackedKeys) {
                recordCapacitySaturated();
                return null;
            }
            return new SlidingWindowCounter(now);
        });
        if (counter != null) {
            counter.recordFailure(now);
        }
    }

    /**
     * 용량 상한 도달로 인한 fail-closed 차단 발생을 기록합니다.
     * <p>
     * 공격 볼륨만큼 매 요청마다 {@code warn} 로그가 찍히면 로그 자체가 2차 DoS 벡터가 되므로,
     * 최초 발생 시 즉시 로그를 남기고 이후에는 {@link #CAPACITY_WARN_LOG_INTERVAL_MS} 주기로
     * 요약만 기록합니다. 누적 발생 횟수는 {@link #getCapacityRejectionCount()}로 외부 메트릭
     * 수집기에 노출할 수 있습니다.
     * </p>
     */
    private void recordCapacitySaturated() {
        capacityRejectionCount.incrementAndGet();
        intervalRejectionCount.incrementAndGet();
        long now = System.currentTimeMillis();
        long last = lastCapacityWarnLogEpochMs.get();
        if (now - last >= CAPACITY_WARN_LOG_INTERVAL_MS
            && lastCapacityWarnLogEpochMs.compareAndSet(last, now)) {
            long summarized = intervalRejectionCount.getAndSet(0);
            log.warn("[RateLimiter] 카운터 맵 용량 상한({})에 도달하여 최근 {}초간 신규 키 {}회를 "
                    + "차단 처리했습니다(누적 {}회). 로그 폭주 방지를 위해 주기 요약만 기록합니다.",
                maxTrackedKeys, CAPACITY_WARN_LOG_INTERVAL_MS / 1000, summarized,
                capacityRejectionCount.get());
        }
    }

    /**
     * 용량 상한으로 인해 fail-closed 처리된 누적 횟수를 반환합니다(외부 메트릭 연동용).
     */
    public long getCapacityRejectionCount() {
        return capacityRejectionCount.get();
    }

    @Override
    public long getRetryAfterSeconds(String key) {
        SlidingWindowCounter counter = counters.get(key);
        if (counter == null) {
            return 0;
        }
        return counter.getRetryAfterSeconds(Instant.now());
    }

    /**
     * 만료된 엔트리를 정리합니다.
     */
    private void cleanup() {
        Instant now = Instant.now();
        int before = counters.size();
        counters.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
        int removed = before - counters.size();
        if (removed > 0) {
            log.debug("[RateLimiter] 만료된 엔트리 {}개 정리 (현재: {}개)", removed, counters.size());
        }
    }

    @PreDestroy
    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // 테스트 가용성을 위한 패키지-프라이빗 메서드
    int getCounterSize() {
        return counters.size();
    }

    /**
     * Sliding Window Counter.
     * 윈도우 내 실패 수를 카운팅하고, 초과 시 차단 시각을 기록합니다.
     */
    private class SlidingWindowCounter {
        private volatile long windowStart;
        private final AtomicInteger count;
        private volatile long blockedUntil; // epoch seconds, 0이면 차단 아님

        SlidingWindowCounter(Instant now) {
            this.windowStart = now.getEpochSecond();
            this.count = new AtomicInteger(0);
            this.blockedUntil = 0;
        }

        synchronized boolean isBlocked(Instant now) {
            long nowEpoch = now.getEpochSecond();

            // 차단 중인지 확인
            if (blockedUntil > 0 && nowEpoch < blockedUntil) {
                return true;
            }

            // 차단이 만료되었으면 리셋
            if (blockedUntil > 0 && nowEpoch >= blockedUntil) {
                resetWindow(nowEpoch);
                return false;
            }

            // 윈도우가 만료되었으면 리셋
            if (nowEpoch - windowStart >= windowSeconds) {
                resetWindow(nowEpoch);
                return false;
            }

            return false;
        }

        synchronized void recordFailure(Instant now) {
            long nowEpoch = now.getEpochSecond();

            // 차단 중이면 기록하지 않음
            if (blockedUntil > 0 && nowEpoch < blockedUntil) {
                return;
            }

            // 차단이 만료되었으면 리셋
            if (blockedUntil > 0 && nowEpoch >= blockedUntil) {
                resetWindow(nowEpoch);
            }

            // 윈도우가 만료되었으면 리셋
            if (nowEpoch - windowStart >= windowSeconds) {
                resetWindow(nowEpoch);
            }

            // 실패 카운트 증가
            int currentCount = count.incrementAndGet();
            if (currentCount > maxRequests) {
                // 차단 시작
                blockedUntil = nowEpoch + blockDurationSeconds;
                log.debug("[RateLimiter] 차단 시작: 윈도우 내 실패 {}회 초과 (최대: {}), 차단 해제: {}초 후",
                    currentCount, maxRequests, blockDurationSeconds);
            }
        }

        long getRetryAfterSeconds(Instant now) {
            long nowEpoch = now.getEpochSecond();
            if (blockedUntil > 0 && nowEpoch < blockedUntil) {
                return blockedUntil - nowEpoch;
            }
            return 0;
        }

        boolean isExpired(Instant now) {
            long nowEpoch = now.getEpochSecond();
            // 차단 중이 아니고, 윈도우도 만료되었으면 정리 대상
            if (blockedUntil > 0) {
                return nowEpoch >= blockedUntil + windowSeconds;
            }
            return nowEpoch - windowStart >= windowSeconds * 2;
        }

        private void resetWindow(long nowEpoch) {
            windowStart = nowEpoch;
            count.set(0); // 리셋 시 카운트 0으로 (실패 기록은 recordFailure에서)
            blockedUntil = 0;
        }
    }
}
