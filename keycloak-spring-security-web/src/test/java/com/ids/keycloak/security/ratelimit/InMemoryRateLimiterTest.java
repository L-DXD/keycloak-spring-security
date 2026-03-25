package com.ids.keycloak.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

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
        void maxRequests까지_실패해도_차단되지_않는다() {
            String key = "ip:192.168.1.1";

            rateLimiter.recordFailure(key);
            rateLimiter.recordFailure(key);
            rateLimiter.recordFailure(key);

            assertThat(rateLimiter.isBlocked(key)).isFalse();
        }

        @Test
        void maxRequests_초과_실패시_차단된다() {
            String key = "ip:192.168.1.1";

            // 3회 실패 (허용 범위)
            for (int i = 0; i < 3; i++) {
                rateLimiter.recordFailure(key);
            }
            assertThat(rateLimiter.isBlocked(key)).isFalse();

            // 4회째 실패 → 차단
            rateLimiter.recordFailure(key);
            assertThat(rateLimiter.isBlocked(key)).isTrue();
        }

        @Test
        void 실패_기록_없이는_차단되지_않는다() {
            String key = "ip:192.168.1.1";

            // recordFailure 호출 없이 isBlocked만 반복 호출
            for (int i = 0; i < 100; i++) {
                assertThat(rateLimiter.isBlocked(key)).isFalse();
            }
        }

        @Test
        void 차단_시_retryAfterSeconds가_양수를_반환한다() {
            String key = "ip:192.168.1.1";

            // 한도 초과 실패
            for (int i = 0; i < 4; i++) {
                rateLimiter.recordFailure(key);
            }

            long retryAfter = rateLimiter.getRetryAfterSeconds(key);
            assertThat(retryAfter).isGreaterThan(0);
            assertThat(retryAfter).isLessThanOrEqualTo(300);
        }

        @Test
        void 차단되지_않은_키는_retryAfterSeconds가_0이다() {
            String key = "ip:192.168.1.1";
            rateLimiter.recordFailure(key);

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
                rateLimiter.recordFailure(key1);
            }
            assertThat(rateLimiter.isBlocked(key1)).isTrue();

            // key2는 여전히 허용
            assertThat(rateLimiter.isBlocked(key2)).isFalse();
        }
    }

    @Nested
    class 윈도우_경과_후_재허용 {

        @Test
        void 차단_경과_후_요청이_다시_허용된다() {
            // windowSeconds=1 (1초), blockDurationSeconds=1로 빠른 테스트
            rateLimiter = new InMemoryRateLimiter(2, 1, 1);
            String key = "ip:10.0.0.1";

            // 한도 초과 실패
            rateLimiter.recordFailure(key);
            rateLimiter.recordFailure(key);
            rateLimiter.recordFailure(key);
            assertThat(rateLimiter.isBlocked(key)).isTrue();

            // 차단 시간 대기 (1초 + 여유)
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // 다시 허용
            assertThat(rateLimiter.isBlocked(key)).isFalse();
        }
    }

    @Nested
    class 동시_접근_스레드_안전성 {

        @Test
        void 동시에_여러_스레드가_실패를_기록해도_정상_동작한다() throws InterruptedException {
            rateLimiter = new InMemoryRateLimiter(10, 60, 300);
            String key = "ip:concurrent-test";
            int threadCount = 50;

            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        rateLimiter.recordFailure(key);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // 50회 실패 기록 → maxRequests=10 초과이므로 차단
            assertThat(rateLimiter.isBlocked(key)).isTrue();
        }
    }

    @Nested
    class blockDuration_설정 {

        @Test
        void blockDurationSeconds가_0이면_windowSeconds와_동일하게_적용된다() {
            // blockDurationSeconds=0 → windowSeconds=1 사용
            rateLimiter = new InMemoryRateLimiter(1, 1, 0);
            String key = "ip:block-test";

            rateLimiter.recordFailure(key);
            rateLimiter.recordFailure(key); // 차단

            long retryAfter = rateLimiter.getRetryAfterSeconds(key);
            // windowSeconds(1)와 동일하게 적용되므로 0~1초 사이
            assertThat(retryAfter).isLessThanOrEqualTo(1);
        }
    }
}
