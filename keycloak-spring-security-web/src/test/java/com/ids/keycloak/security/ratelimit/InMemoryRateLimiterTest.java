package com.ids.keycloak.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class InMemoryRateLimiterTest {

    private InMemoryRateLimiter rateLimiter;

    @AfterEach
    void tearDown() {
        if (rateLimiter != null) {
            rateLimiter.shutdown();
        }
    }

    @Nested
    class 윈도우_내_요청_제한 {

        @BeforeEach
        void setUp() {
            // maxRequests=3, windowSeconds=60, blockDurationSeconds=300
            rateLimiter = new InMemoryRateLimiter(3, 60, 300);
        }

        @Test
        void maxRequests까지_허용된다() {
            String key = "ip:192.168.1.1";

            assertThat(rateLimiter.tryAcquire(key)).isTrue();
            assertThat(rateLimiter.tryAcquire(key)).isTrue();
            assertThat(rateLimiter.tryAcquire(key)).isTrue();
        }

        @Test
        void maxRequests_초과시_차단된다() {
            String key = "ip:192.168.1.1";

            // 3회 허용
            for (int i = 0; i < 3; i++) {
                assertThat(rateLimiter.tryAcquire(key)).isTrue();
            }

            // 4회째부터 차단
            assertThat(rateLimiter.tryAcquire(key)).isFalse();
            assertThat(rateLimiter.tryAcquire(key)).isFalse();
        }

        @Test
        void 차단_시_retryAfterSeconds가_양수를_반환한다() {
            String key = "ip:192.168.1.1";

            // 한도 초과
            for (int i = 0; i < 4; i++) {
                rateLimiter.tryAcquire(key);
            }

            long retryAfter = rateLimiter.getRetryAfterSeconds(key);
            assertThat(retryAfter).isGreaterThan(0);
            assertThat(retryAfter).isLessThanOrEqualTo(300);
        }

        @Test
        void 차단되지_않은_키는_retryAfterSeconds가_0이다() {
            String key = "ip:192.168.1.1";
            rateLimiter.tryAcquire(key);

            assertThat(rateLimiter.getRetryAfterSeconds(key)).isEqualTo(0);
        }

        @Test
        void 존재하지_않는_키는_retryAfterSeconds가_0이다() {
            assertThat(rateLimiter.getRetryAfterSeconds("unknown")).isEqualTo(0);
        }

        @Test
        void 서로_다른_키는_독립적으로_제한된다() {
            String key1 = "ip:192.168.1.1";
            String key2 = "ip:192.168.1.2";

            // key1을 한도까지 소진
            for (int i = 0; i < 4; i++) {
                rateLimiter.tryAcquire(key1);
            }
            assertThat(rateLimiter.tryAcquire(key1)).isFalse();

            // key2는 여전히 허용
            assertThat(rateLimiter.tryAcquire(key2)).isTrue();
        }
    }

    @Nested
    class 윈도우_경과_후_재허용 {

        @Test
        void 윈도우_경과_후_요청이_다시_허용된다() {
            // windowSeconds=1 (1초), blockDurationSeconds=1로 빠른 테스트
            rateLimiter = new InMemoryRateLimiter(2, 1, 1);
            String key = "ip:10.0.0.1";

            // 한도 초과
            assertThat(rateLimiter.tryAcquire(key)).isTrue();
            assertThat(rateLimiter.tryAcquire(key)).isTrue();
            assertThat(rateLimiter.tryAcquire(key)).isFalse();

            // 차단 시간 대기 (1초 + 여유)
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // 다시 허용
            assertThat(rateLimiter.tryAcquire(key)).isTrue();
        }
    }

    @Nested
    class 동시_접근_스레드_안전성 {

        @Test
        void 동시에_여러_스레드가_접근해도_maxRequests를_초과하여_허용하지_않는다() throws InterruptedException {
            rateLimiter = new InMemoryRateLimiter(10, 60, 300);
            String key = "ip:concurrent-test";
            int threadCount = 50;

            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger acquiredCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        if (rateLimiter.tryAcquire(key)) {
                            acquiredCount.incrementAndGet();
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // maxRequests=10이므로 최대 10번까지만 허용
            assertThat(acquiredCount.get()).isLessThanOrEqualTo(10);
            assertThat(acquiredCount.get()).isGreaterThan(0);
        }
    }

    @Nested
    class blockDuration_설정 {

        @Test
        void blockDurationSeconds가_0이면_windowSeconds와_동일하게_적용된다() {
            // blockDurationSeconds=0 → windowSeconds=1 사용
            rateLimiter = new InMemoryRateLimiter(1, 1, 0);
            String key = "ip:block-test";

            rateLimiter.tryAcquire(key);
            rateLimiter.tryAcquire(key); // 차단

            long retryAfter = rateLimiter.getRetryAfterSeconds(key);
            // windowSeconds(1)와 동일하게 적용되므로 0~1초 사이
            assertThat(retryAfter).isLessThanOrEqualTo(1);
        }
    }
}
