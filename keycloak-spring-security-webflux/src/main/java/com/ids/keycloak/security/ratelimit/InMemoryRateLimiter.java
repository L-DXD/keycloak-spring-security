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
 *
 * <p>servlet 모듈의 {@code InMemoryRateLimiter}와 동일한 구현입니다.
 * Sliding Window Counter 알고리즘을 사용하여 인증 실패를 제한합니다.
 * 윈도우 시간 내에 {@code maxRequests}를 초과하면 {@code blockDurationSeconds} 동안 차단합니다.</p>
 *
 * <p>주기적으로 만료된 엔트리를 정리하여 메모리 누수를 방지합니다.</p>
 *
 * <p><b>용량 상한 정책(CWE-400 방어):</b> {@code maxTrackedKeys}로 동시 추적 가능한 키 수를 제한합니다.
 * 맵이 상한에 도달한 상태에서 아직 추적되지 않은 새 키가 유입되면 <b>fail-closed</b>로
 * 즉시 차단 처리합니다. 이미 추적 중인 키는 상한과 무관하게 정상적으로 판단됩니다.</p>
 */
@Slf4j
public class InMemoryRateLimiter implements RateLimiter {

  /** {@code maxTrackedKeys}를 지정하지 않는 하위 호환 생성자의 기본 상한. */
  private static final int DEFAULT_MAX_TRACKED_KEYS = 100_000;

  private final int maxRequests;
  private final long windowSeconds;
  private final long blockDurationSeconds;
  private final int maxTrackedKeys;

  private final Map<String, SlidingWindowCounter> counters = new ConcurrentHashMap<>();
  private final ScheduledExecutorService cleanupExecutor;

  public InMemoryRateLimiter(int maxRequests, long windowSeconds, long blockDurationSeconds) {
    this(maxRequests, windowSeconds, blockDurationSeconds, DEFAULT_MAX_TRACKED_KEYS);
  }

  public InMemoryRateLimiter(int maxRequests, long windowSeconds, long blockDurationSeconds,
      int maxTrackedKeys) {
    this.maxRequests = maxRequests;
    this.windowSeconds = windowSeconds;
    this.blockDurationSeconds = blockDurationSeconds > 0 ? blockDurationSeconds : windowSeconds;
    this.maxTrackedKeys = maxTrackedKeys > 0 ? maxTrackedKeys : DEFAULT_MAX_TRACKED_KEYS;

    this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread thread = new Thread(r, "reactive-rate-limit-cleanup");
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
        log.warn("[RateLimiter] 카운터 맵 용량 상한({})에 도달하여 새 키를 차단 처리합니다.", maxTrackedKeys);
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
        log.warn("[RateLimiter] 카운터 맵 용량 상한({})에 도달하여 새 키({})를 추적하지 않습니다.",
            maxTrackedKeys, k);
        return null;
      }
      return new SlidingWindowCounter(now);
    });
    if (counter != null) {
      counter.recordFailure(now);
    }
  }

  @Override
  public long getRetryAfterSeconds(String key) {
    SlidingWindowCounter counter = counters.get(key);
    if (counter == null) {
      return 0;
    }
    return counter.getRetryAfterSeconds(Instant.now());
  }

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

  /**
   * Sliding Window Counter.
   */
  private class SlidingWindowCounter {

    private volatile long windowStart;
    private final AtomicInteger count;
    private volatile long blockedUntil;

    SlidingWindowCounter(Instant now) {
      this.windowStart = now.getEpochSecond();
      this.count = new AtomicInteger(0);
      this.blockedUntil = 0;
    }

    synchronized boolean isBlocked(Instant now) {
      long nowEpoch = now.getEpochSecond();
      if (blockedUntil > 0 && nowEpoch < blockedUntil) {
        return true;
      }
      if (blockedUntil > 0 && nowEpoch >= blockedUntil) {
        resetWindow(nowEpoch);
        return false;
      }
      if (nowEpoch - windowStart >= windowSeconds) {
        resetWindow(nowEpoch);
        return false;
      }
      return false;
    }

    synchronized void recordFailure(Instant now) {
      long nowEpoch = now.getEpochSecond();
      if (blockedUntil > 0 && nowEpoch < blockedUntil) {
        return;
      }
      if (blockedUntil > 0 && nowEpoch >= blockedUntil) {
        resetWindow(nowEpoch);
      }
      if (nowEpoch - windowStart >= windowSeconds) {
        resetWindow(nowEpoch);
      }
      int currentCount = count.incrementAndGet();
      if (currentCount > maxRequests) {
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
      if (blockedUntil > 0) {
        return nowEpoch >= blockedUntil + windowSeconds;
      }
      return nowEpoch - windowStart >= windowSeconds * 2;
    }

    private void resetWindow(long nowEpoch) {
      windowStart = nowEpoch;
      count.set(0);
      blockedUntil = 0;
    }
  }
}
