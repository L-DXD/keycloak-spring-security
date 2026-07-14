package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.lang.reflect.Field;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

class IndexedMapSessionRepositoryTest {

    private IndexedMapSessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new IndexedMapSessionRepository();
    }

    /**
     * 0-arg/1-arg 생성자가 데몬 정리 스레드를 즉시 시작하므로, 매 테스트가 끝날 때마다
     * shutdown()으로 회수하지 않으면 테스트 스위트 전체에서 스레드가 계속 누적된다.
     */
    @AfterEach
    void tearDown() {
        if (repository != null) {
            repository.shutdown();
        }
    }

    /**
     * 지정된 조건이 충족될 때까지 폴링 대기한다. 스케줄러(별도 데몬 스레드)가
     * 비동기로 수행하는 정리 작업의 결과를 검증하기 위한 테스트 전용 헬퍼다.
     */
    private static void awaitUntil(BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadlineMillis = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() < deadlineMillis) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(condition.getAsBoolean())
            .as("조건이 제한 시간(%s) 내에 충족되지 않았습니다.", timeout)
            .isTrue();
    }

    private static ScheduledExecutorService extractCleanupExecutor(IndexedMapSessionRepository target) throws Exception {
        Field field = IndexedMapSessionRepository.class.getDeclaredField("cleanupExecutor");
        field.setAccessible(true);
        return (ScheduledExecutorService) field.get(target);
    }

    @Nested
    class 정상_케이스 {
        @Test
        void 세션을_생성하고_저장하고_조회한다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();

            // When
            repository.save(session);
            MapSession found = repository.findById(sessionId);

            // Then
            assertThat(found).isNotNull();
            assertThat(found.getId()).isEqualTo(sessionId);
        }

        @Test
        void Principal_Name으로_세션을_검색한다() {
            // Given
            MapSession sessionA = repository.createSession();
            sessionA.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            MapSession sessionB = repository.createSession();
            sessionB.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            MapSession sessionC = repository.createSession();
            sessionC.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user2");

            repository.save(sessionA);
            repository.save(sessionB);
            repository.save(sessionC);

            // When
            Map<String, MapSession> result = repository.findByPrincipalName("user1");

            // Then
            assertThat(result).hasSize(2);
            assertThat(result).containsKey(sessionA.getId());
            assertThat(result).containsKey(sessionB.getId());
            assertThat(result).doesNotContainKey(sessionC.getId());
        }

        @Test
        void findByIndexNameAndIndexValue로_Principal_Name_검색이_가능하다() {
            // Given
            MapSession session = repository.createSession();
            session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            repository.save(session);

            // When
            Map<String, MapSession> result = repository.findByIndexNameAndIndexValue(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");

            // Then
            assertThat(result).hasSize(1);
            assertThat(result).containsKey(session.getId());
        }

        @Test
        void 세션을_삭제한다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();
            repository.save(session);

            // When
            repository.deleteById(sessionId);

            // Then
            assertThat(repository.findById(sessionId)).isNull();
        }

        @Test
        void 기본_만료_시간을_설정한다() {
            // Given
            Duration customDuration = Duration.ofHours(1);
            repository.setDefaultMaxInactiveInterval(customDuration);

            // When
            MapSession session = repository.createSession();

            // Then
            assertThat(session.getMaxInactiveInterval()).isEqualTo(customDuration);
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 만료된_세션은_조회되지_않고_삭제된다() {
            // Given
            MapSession session = repository.createSession();
            String sessionId = session.getId();
            session.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            session.setMaxInactiveInterval(Duration.ofMinutes(30));
            repository.save(session);

            // When
            MapSession found = repository.findById(sessionId);

            // Then
            assertThat(found).isNull();
        }

        @Test
        void 존재하지_않는_ID로_조회하면_null을_반환한다() {
            // When
            MapSession found = repository.findById("non-existent-id");

            // Then
            assertThat(found).isNull();
        }

        @Test
        void 지원하지_않는_인덱스로_검색하면_빈_맵을_반환한다() {
            // Given
            MapSession session = repository.createSession();
            session.setAttribute("CUSTOM_INDEX", "value");
            repository.save(session);

            // When
            Map<String, MapSession> result = repository.findByIndexNameAndIndexValue("UNSUPPORTED_INDEX", "value");

            // Then
            assertThat(result).isEmpty();
        }

        @Test
        void 세션_ID가_변경되면_기존_세션이_제거된다() {
            // Given
            MapSession session = repository.createSession();
            String originalId = session.getId();
            repository.save(session);

            // When - 세션 ID 변경
            session.changeSessionId();
            String newId = session.getId();
            repository.save(session);

            // Then
            assertThat(repository.findById(originalId)).isNull();
            assertThat(repository.findById(newId)).isNotNull();
        }

        @Test
        void 만료된_세션은_Principal_Name_검색에서_제외된다() {
            // Given
            MapSession validSession = repository.createSession();
            validSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            repository.save(validSession);

            MapSession expiredSession = repository.createSession();
            expiredSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            expiredSession.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            expiredSession.setMaxInactiveInterval(Duration.ofMinutes(30));
            repository.save(expiredSession);

            // When
            Map<String, MapSession> result = repository.findByPrincipalName("user1");

            // Then
            assertThat(result).hasSize(1);
            assertThat(result).containsKey(validSession.getId());
        }
    }

    /**
     * Advisory 6(CWE-400/CWE-770): maxSessions 도달 시 fail-closed 정책을 검증한다.
     * 신규(추적된 적 없는) 세션만 거부 대상이며, 이미 추적 중인 세션의 갱신·조회·삭제와
     * 세션 고정 방지를 위한 ID 재발급 저장은 상한과 무관하게 항상 성공해야 한다.
     */
    @Nested
    class 용량_상한_fail_closed {

        private static final int MAX_SESSIONS = 3;

        private Map<String, MapSession> backingMap;
        private IndexedMapSessionRepository boundedRepository;

        @BeforeEach
        void setUpBounded() {
            backingMap = new ConcurrentHashMap<>();
            // 정리 스케줄이 테스트 도중 개입하지 않도록 충분히 긴 주기로 설정한다.
            boundedRepository = new IndexedMapSessionRepository(backingMap, MAX_SESSIONS, Duration.ofHours(1));
        }

        @AfterEach
        void tearDownBounded() {
            boundedRepository.shutdown();
        }

        private MapSession fillToCapacity() {
            MapSession last = null;
            for (int i = 0; i < MAX_SESSIONS; i++) {
                MapSession session = boundedRepository.createSession();
                boundedRepository.save(session);
                last = session;
            }
            return last;
        }

        @Test
        void 상한_도달_전에는_신규_세션_저장이_정상적으로_허용된다() {
            MapSession last = fillToCapacity();

            assertThat(backingMap).hasSize(MAX_SESSIONS);
            assertThat(boundedRepository.findById(last.getId())).isNotNull();
        }

        @Test
        void 상한_도달_후_추적된_적_없는_신규_세션_저장은_거부된다() {
            // Given
            fillToCapacity();
            long rejectionBefore = boundedRepository.getCapacityRejectionCount();

            // When
            MapSession newSession = boundedRepository.createSession();
            boundedRepository.save(newSession);

            // Then
            assertThat(boundedRepository.findById(newSession.getId())).isNull();
            assertThat(backingMap).hasSize(MAX_SESSIONS);
            assertThat(boundedRepository.getCapacityRejectionCount()).isEqualTo(rejectionBefore + 1);
        }

        @Test
        void 상한_도달_후에도_기존_세션의_갱신은_상한과_무관하게_성공한다() {
            // Given
            MapSession existing = fillToCapacity();

            // When - 이미 추적 중인 세션(ID 변경 없음)을 다시 저장(갱신)
            existing.setAttribute("updated", true);
            boundedRepository.save(existing);

            // Then
            MapSession found = boundedRepository.findById(existing.getId());
            assertThat(found).isNotNull();
            Boolean updated = found.getAttribute("updated");
            assertThat(updated).isTrue();
            assertThat(backingMap).hasSize(MAX_SESSIONS);
        }

        @Test
        void 상한_도달_후에도_기존_세션의_조회와_삭제는_상한과_무관하게_성공한다() {
            // Given
            MapSession existing = fillToCapacity();

            // When / Then - 조회
            assertThat(boundedRepository.findById(existing.getId())).isNotNull();

            // When - 삭제
            boundedRepository.deleteById(existing.getId());

            // Then
            assertThat(boundedRepository.findById(existing.getId())).isNull();
            assertThat(backingMap).hasSize(MAX_SESSIONS - 1);
        }

        @Test
        void 상한_도달_상태에서도_세션_고정_방지를_위한_ID_재발급_저장은_성공한다() {
            // Given - 상한까지 채워진 세션 중 하나를 익명(로그인 전) 세션으로 취급
            MapSession anonymousSession = fillToCapacity();
            String originalId = anonymousSession.getId();

            // When - 인증 성공 시점의 일반적인 처리: 세션 고정 공격 방지를 위해 ID를 교체 후 재저장
            anonymousSession.changeSessionId();
            anonymousSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
            String newId = anonymousSession.getId();
            boundedRepository.save(anonymousSession);

            // Then - 상한이 가득 찬 상태여도 강제 로그아웃(저장 거부) 없이 새 ID로 정상 저장된다
            assertThat(boundedRepository.findById(originalId)).isNull();
            assertThat(boundedRepository.findById(newId)).isNotNull();
            assertThat(backingMap).hasSize(MAX_SESSIONS);
        }
    }

    /**
     * Advisory 6: {@code ConcurrentHashMap#compute}는 서로 다른 신규 키에 대해서는
     * 동시 실행될 수 있어, maxSessions는 정확한 하드 리밋이 아니라 근사(soft) 상한이다.
     * 동시에 신규 세션을 삽입해도 초과 폭이 경합 스레드 수 이내로 유한하게 제한되고,
     * 맵 자체의 무결성(예외 없음, 데이터 손상 없음)이 유지되는지를 검증한다.
     */
    @Nested
    class 동시_삽입_soft_cap_초과폭_제한 {

        @Test
        void 동시에_많은_신규_세션이_삽입되어도_초과폭은_스레드_수_이내로_제한된다() throws Exception {
            int maxSessions = 20;
            int threadCount = 50;
            Map<String, MapSession> backingMap = new ConcurrentHashMap<>();
            IndexedMapSessionRepository boundedRepository =
                new IndexedMapSessionRepository(backingMap, maxSessions, Duration.ofHours(1));

            try {
                // 상한 바로 직전까지 채워, 모든 스레드의 경합 지점을 정확히 상한 근처로 맞춘다.
                for (int i = 0; i < maxSessions - 1; i++) {
                    boundedRepository.save(boundedRepository.createSession());
                }
                assertThat(backingMap).hasSize(maxSessions - 1);

                ExecutorService executor = Executors.newFixedThreadPool(threadCount);
                CyclicBarrier barrier = new CyclicBarrier(threadCount);
                CountDownLatch doneLatch = new CountDownLatch(threadCount);
                List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());

                for (int i = 0; i < threadCount; i++) {
                    executor.submit(() -> {
                        try {
                            barrier.await(5, TimeUnit.SECONDS); // 동시 진입 지점 정렬(경합 유발)
                            MapSession session = boundedRepository.createSession();
                            boundedRepository.save(session);
                        } catch (Throwable t) {
                            failures.add(t);
                        } finally {
                            doneLatch.countDown();
                        }
                    });
                }

                assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();
                executor.shutdown();

                // Then
                assertThat(failures).as("동시 저장 중 예외가 발생하지 않아야 한다(맵 무결성)").isEmpty();

                int finalSize = backingMap.size();
                // 상한은 최소한 채워진다(첫 통과 스레드는 항상 성공)
                assertThat(finalSize).isGreaterThanOrEqualTo(maxSessions);
                // soft-cap이므로 초과할 수는 있으나, 초과 폭은 동시에 경합한 스레드 수 이내로 유한하다.
                assertThat(finalSize).isLessThanOrEqualTo((maxSessions - 1) + threadCount);
            } finally {
                boundedRepository.shutdown();
            }
        }
    }

    /**
     * Advisory 6: 만료된 세션의 물리적 제거를 동일 세션 재접근(findById 등) 없이
     * 전용 데몬 스케줄러가 주기적으로 전담 수행하는지 검증한다.
     */
    @Nested
    class 스케줄_기반_만료_세션_정리 {

        private IndexedMapSessionRepository scheduledRepository;

        @AfterEach
        void tearDownScheduled() {
            if (scheduledRepository != null) {
                scheduledRepository.shutdown();
            }
        }

        @Test
        void 만료된_세션은_재접근_없이_스케줄러가_주기적으로_제거한다() throws Exception {
            // Given - 정리 주기를 50ms로 짧게 설정
            Map<String, MapSession> backingMap = new ConcurrentHashMap<>();
            scheduledRepository = new IndexedMapSessionRepository(backingMap, 100, Duration.ofMillis(50));

            MapSession expiredSession = scheduledRepository.createSession();
            expiredSession.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            expiredSession.setMaxInactiveInterval(Duration.ofMinutes(30));
            scheduledRepository.save(expiredSession);
            String expiredId = expiredSession.getId();

            assertThat(backingMap).containsKey(expiredId);

            // When / Then - findById 등 재접근 없이 backingMap을 직접 관찰하여
            // 스케줄러가 자체적으로 만료 세션을 제거하는지 확인한다.
            awaitUntil(() -> !backingMap.containsKey(expiredId), Duration.ofSeconds(2));
            assertThat(backingMap).doesNotContainKey(expiredId);
        }

        @Test
        void 유효한_세션은_스케줄_정리_대상에서_제외된다() throws Exception {
            // Given
            Map<String, MapSession> backingMap = new ConcurrentHashMap<>();
            scheduledRepository = new IndexedMapSessionRepository(backingMap, 100, Duration.ofMillis(50));

            MapSession validSession = scheduledRepository.createSession();
            scheduledRepository.save(validSession);

            // When - 정리 스케줄이 여러 차례 돌 만큼 대기
            Thread.sleep(300);

            // Then
            assertThat(backingMap).containsKey(validSession.getId());
        }
    }

    /**
     * Advisory 6: {@code @PreDestroy}로 등록된 {@link IndexedMapSessionRepository#shutdown()}이
     * 정리 스케줄러 스레드를 실제로 종료시키는지(스레드 누수 방지) 검증한다.
     */
    @Nested
    class PreDestroy_스레드_종료 {

        @Test
        void shutdown_호출_후_정리_스케줄러가_종료된다() throws Exception {
            // Given
            ScheduledExecutorService executor = extractCleanupExecutor(repository);
            assertThat(executor.isShutdown()).isFalse();

            // When
            repository.shutdown();

            // Then
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
            assertThat(executor.isShutdown()).isTrue();
            assertThat(executor.isTerminated()).isTrue();
        }

        @Test
        void shutdown_이후에는_스케줄_정리가_더_이상_동작하지_않는다() throws Exception {
            // Given - 정리 주기를 50ms로 짧게 설정한 별도 인스턴스
            Map<String, MapSession> backingMap = new ConcurrentHashMap<>();
            IndexedMapSessionRepository shortIntervalRepository =
                new IndexedMapSessionRepository(backingMap, 100, Duration.ofMillis(50));

            // When - 스케줄이 시작되기도 전에 즉시 종료
            shortIntervalRepository.shutdown();

            MapSession expiredSession = shortIntervalRepository.createSession();
            expiredSession.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
            expiredSession.setMaxInactiveInterval(Duration.ofMinutes(30));
            shortIntervalRepository.save(expiredSession);

            // Then - 정리 주기(50ms)보다 충분히 긴 시간이 지나도, 종료된 스케줄러는 더 이상
            // 정리를 수행하지 않으므로 만료 세션이 맵에 그대로 남아있어야 한다.
            Thread.sleep(300);
            assertThat(backingMap).containsKey(expiredSession.getId());
        }

        @Test
        void shutdown_이후에도_save_find_delete는_예외없이_안전하게_동작한다() {
            // Given
            repository.shutdown();

            // When / Then - 스케줄러 종료가 다른 기능에 부작용을 주지 않아야 한다.
            MapSession session = repository.createSession();
            assertThatCode(() -> repository.save(session)).doesNotThrowAnyException();
            assertThat(repository.findById(session.getId())).isNotNull();
            assertThatCode(() -> repository.deleteById(session.getId())).doesNotThrowAnyException();
        }
    }

    /**
     * Advisory 6 code-review Low 4: {@code findByPrincipalName()}은 만료 세션을 결과에서
     * 필터링하는 계약은 유지하되, 물리적 삭제(맵에서 제거)는 더 이상 이 메서드가
     * 수행하지 않고 스케줄러가 전담한다. 시맨틱 변경을 검증한다.
     */
    @Nested
    class findByPrincipalName_필터링과_물리삭제_분리 {

        @Test
        void 만료된_세션은_결과에서는_제외되지만_물리적으로_삭제되지는_않는다() throws Exception {
            // Given - 정리 스케줄이 테스트 도중 개입하지 않도록 충분히 긴 주기로 설정
            Map<String, MapSession> backingMap = new ConcurrentHashMap<>();
            IndexedMapSessionRepository repo =
                new IndexedMapSessionRepository(backingMap, 100, Duration.ofHours(1));

            try {
                MapSession expiredSession = repo.createSession();
                expiredSession.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "user1");
                expiredSession.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)));
                expiredSession.setMaxInactiveInterval(Duration.ofMinutes(30));
                repo.save(expiredSession);
                String expiredId = expiredSession.getId();

                // When
                Map<String, MapSession> result = repo.findByPrincipalName("user1");

                // Then - 계약: 조회 결과에서는 제외된다
                assertThat(result).doesNotContainKey(expiredId);
                // Then - 시맨틱 변경: 물리 삭제는 스케줄러 전담이므로, 조회 호출만으로는
                // 맵에서 제거되지 않는다.
                assertThat(backingMap).containsKey(expiredId);
            } finally {
                repo.shutdown();
            }
        }
    }
}
