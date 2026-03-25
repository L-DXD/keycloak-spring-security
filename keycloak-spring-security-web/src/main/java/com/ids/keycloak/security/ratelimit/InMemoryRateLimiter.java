package com.ids.keycloak.security.ratelimit;

import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.extern.slf4j.Slf4j;

/**
 * {@link ConcurrentHashMap} 기반 인메모리 Rate Limiter 구현체입니다.
 * <p>
 * Sliding Window Counter 알고리즘을 사용하여 요청을 제한합니다.
 * 윈도우 시간 내에 {@code maxRequests}를 초과하면 {@code blockDurationSeconds} 동안 차단합니다.
 * </p>
 * <p>
 * 주기적으로 만료된 엔트리를 정리하여 메모리 누수를 방지합니다.
 * </p>
 */
@Slf4j
public class InMemoryRateLimiter implements RateLimiter {

    private final int maxRequests;
    private final long windowSeconds;
    private final long blockDurationSeconds;

    private final Map<String, SlidingWindowCounter> counters = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor;

    public InMemoryRateLimiter(int maxRequests, long windowSeconds, long blockDurationSeconds) {
        this.maxRequests = maxRequests;
        this.windowSeconds = windowSeconds;
        this.blockDurationSeconds = blockDurationSeconds > 0 ? blockDurationSeconds : windowSeconds;

        // 만료된 엔트리 정리 스케줄러 (5분마다)
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "rate-limit-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        this.cleanupExecutor.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.MINUTES);
    }

    @Override
    public boolean tryAcquire(String key) {
        Instant now = Instant.now();
        SlidingWindowCounter counter = counters.compute(key, (k, existing) -> {
            if (existing == null) {
                return new SlidingWindowCounter(now);
            }
            return existing;
        });

        return counter.tryAcquire(now);
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
     * 윈도우 내 요청 수를 카운팅하고, 초과 시 차단 시각을 기록합니다.
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

        synchronized boolean tryAcquire(Instant now) {
            long nowEpoch = now.getEpochSecond();

            // 차단 중인지 확인
            if (blockedUntil > 0 && nowEpoch < blockedUntil) {
                return false;
            }

            // 차단이 만료되었으면 리셋
            if (blockedUntil > 0 && nowEpoch >= blockedUntil) {
                resetWindow(nowEpoch);
                return true;
            }

            // 윈도우가 만료되었으면 리셋
            if (nowEpoch - windowStart >= windowSeconds) {
                resetWindow(nowEpoch);
                return true;
            }

            // 윈도우 내 카운트 증가
            int currentCount = count.incrementAndGet();
            if (currentCount > maxRequests) {
                // 차단 시작
                blockedUntil = nowEpoch + blockDurationSeconds;
                log.debug("[RateLimiter] 차단 시작: 윈도우 내 {}회 초과 (최대: {}), 차단 해제: {}초 후",
                    currentCount, maxRequests, blockDurationSeconds);
                return false;
            }

            return true;
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
            count.set(1); // 현재 요청 포함
            blockedUntil = 0;
        }
    }
}
