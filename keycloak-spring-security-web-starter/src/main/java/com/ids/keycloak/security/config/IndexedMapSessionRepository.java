package com.ids.keycloak.security.config;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * {@link FindByIndexNameSessionRepository}를 구현하는 인-메모리 세션 저장소입니다.
 * <p>
 * Principal Name(사용자 ID)을 기준으로 세션을 검색할 수 있어,
 * 백채널 로그아웃 시 특정 사용자의 모든 세션을 조회하고 삭제할 수 있습니다.
 * </p>
 * <p>
 * <b>스케줄 기반 만료 세션 정리(CWE-400/CWE-770 방어):</b> 저장소 내부의 전용 데몬
 * 스레드가 {@code cleanupInterval} 주기로 만료 세션을 스캔해 제거합니다. 기존에는
 * 동일 세션 ID가 재조회되거나 {@link #findByPrincipalName(String)}이 우연히 호출될
 * 때만 만료 세션이 제거되어, 조회되지 않는 버려진 익명 세션이 무한정 쌓일 수
 * 있었습니다. 이 스케줄은 애플리케이션의 {@code @EnableScheduling} 설정에 의존하지
 * 않습니다 — 라이브러리가 host 애플리케이션에 스케줄링 인프라를 강제하면, host가
 * 인지하지 못한 채 잠들어 있던 다른 {@code @Scheduled} 메서드가 의도치 않게
 * 활성화되는 부작용이 생길 수 있기 때문입니다.
 * </p>
 * <p>
 * <b>용량 상한 정책(CWE-400 방어):</b> {@code maxSessions}로 동시에 유지 가능한
 * 세션 수를 제한합니다. 상한에 도달한 상태에서 아직 추적되지 않은 신규 세션이
 * 유입되면 <b>fail-closed</b>로 저장을 거부합니다(세션 쿠키를 보관하지 않고 OIDC
 * 로그인을 반복 개시하는 공격으로 인한 메모리 무한 증가를 방지하기 위해, 신규
 * 세션을 무조건 저장하는 대신 거부를 택함). 이미 추적 중인 세션은 상한과 무관하게
 * 정상적으로 갱신·조회됩니다 — 공격자가 용량을 소진시켜 이미 로그인된 사용자의
 * 세션을 강제로 축출(evict)할 수는 없습니다.
 * </p>
 * <p>
 * <b>운영 배포 안내:</b> 이 저장소는 JVM 힙 기반 단일 인스턴스 저장소입니다.
 * 인터넷에 노출되는 운영 환경에서는 상한·TTL이 있는 외부 저장소(Redis 등)로
 * 전환하는 것을 권장합니다.
 * </p>
 */
@Slf4j
public class IndexedMapSessionRepository implements FindByIndexNameSessionRepository<MapSession> {

    /** {@code maxSessions}를 지정하지 않는 하위 호환 생성자의 기본 상한. */
    private static final int DEFAULT_MAX_SESSIONS = 10_000;

    /** 스케줄 정리 주기를 지정하지 않는 하위 호환 생성자의 기본 주기. */
    private static final Duration DEFAULT_CLEANUP_INTERVAL = Duration.ofMinutes(5);

    /** 용량 상한 도달 경고 로그를 요약해서 남기는 주기(밀리초). 로그 폭주(2차 DoS) 방지용. */
    private static final long CAPACITY_WARN_LOG_INTERVAL_MS = 60_000L;

    /**
     * Principal Name을 저장하기 위한 세션 속성 키.
     * Spring Security는 이 키에 인증된 사용자의 이름을 저장합니다.
     */
    public static final String PRINCIPAL_NAME_INDEX_NAME = FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

    private final Map<String, MapSession> sessions;
    private final int maxSessions;
    private final ScheduledExecutorService cleanupExecutor;
    private Duration defaultMaxInactiveInterval;

    /** 용량 상한으로 인한 누적 거부(신규 세션 저장 거부) 횟수. 외부 메트릭 수집용으로 노출. */
    private final AtomicLong capacityRejectionCount = new AtomicLong(0);
    /** 마지막 요약 로그 이후 발생한 용량 상한 거부 횟수. */
    private final AtomicLong intervalRejectionCount = new AtomicLong(0);
    /** 마지막으로 용량 상한 경고 로그를 남긴 시각(epoch millis). */
    private final AtomicLong lastCapacityWarnLogEpochMs = new AtomicLong(0);

    public IndexedMapSessionRepository() {
        this(new ConcurrentHashMap<>());
    }

    public IndexedMapSessionRepository(Map<String, MapSession> sessions) {
        this(sessions, DEFAULT_MAX_SESSIONS, DEFAULT_CLEANUP_INTERVAL);
    }

    /**
     * 세션 저장소를 생성하고, 만료 세션 정리를 위한 스케줄을 즉시 시작합니다.
     *
     * @param sessions        세션을 보관할 맵 (동시성 안전을 위해 {@link ConcurrentHashMap} 권장)
     * @param maxSessions     동시에 유지 가능한 최대 세션 수 (0 이하이면 {@link #DEFAULT_MAX_SESSIONS}로 대체)
     * @param cleanupInterval 만료 세션 정리 스케줄 주기 (null이거나 0 이하이면 {@link #DEFAULT_CLEANUP_INTERVAL}로 대체)
     */
    public IndexedMapSessionRepository(Map<String, MapSession> sessions, int maxSessions, Duration cleanupInterval) {
        this.sessions = sessions;
        this.defaultMaxInactiveInterval = Duration.ofMinutes(30);
        this.maxSessions = maxSessions > 0 ? maxSessions : DEFAULT_MAX_SESSIONS;

        Duration interval = (cleanupInterval != null && !cleanupInterval.isNegative() && !cleanupInterval.isZero())
            ? cleanupInterval
            : DEFAULT_CLEANUP_INTERVAL;
        long intervalMillis = interval.toMillis();

        // 만료된 세션 정리 스케줄러 - 자체 데몬 스레드로 실행하여 host 애플리케이션의
        // @EnableScheduling 설정에 의존하지 않음(starter가 host의 스케줄링 인프라에
        // 부작용을 주지 않기 위함).
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "keycloak-session-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        this.cleanupExecutor.scheduleAtFixedRate(
            this::cleanExpiredSessionsSafely, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * 기본 세션 만료 시간을 설정합니다.
     *
     * @param defaultMaxInactiveInterval 기본 비활성 시간 (기본값: 30분)
     */
    public void setDefaultMaxInactiveInterval(Duration defaultMaxInactiveInterval) {
        this.defaultMaxInactiveInterval = defaultMaxInactiveInterval;
    }

    @Override
    public MapSession createSession() {
        MapSession session = new MapSession();
        session.setMaxInactiveInterval(this.defaultMaxInactiveInterval);
        return session;
    }

    @Override
    public void save(MapSession session) {
        if (!session.getId().equals(session.getOriginalId())) {
            this.sessions.remove(session.getOriginalId());
        }

        MapSession copy = new MapSession(session);
        String id = session.getId();

        // ConcurrentHashMap#compute는 동일 키에 대해 원자적으로 실행되므로,
        // "신규 키 여부 확인 + 용량 검사 + 삽입"이 하나의 원자적 단위로 처리되어
        // 신규 세션 삽입 경로의 race condition(상한 초과)을 방지합니다.
        // 이미 추적 중인 세션(existing != null)의 갱신은 상한 검사 없이 항상 허용합니다.
        this.sessions.compute(id, (key, existing) -> {
            if (existing != null) {
                return copy;
            }
            if (this.sessions.size() >= this.maxSessions) {
                recordCapacitySaturated(id);
                return null; // 신규 세션 저장 거부(fail-closed) - 상한 유지
            }
            return copy;
        });
    }

    @Override
    public MapSession findById(String id) {
        MapSession saved = this.sessions.get(id);
        if (saved == null) {
            return null;
        }
        if (saved.isExpired()) {
            deleteById(id);
            return null;
        }
        return new MapSession(saved);
    }

    @Override
    public void deleteById(String id) {
        this.sessions.remove(id);
    }

    /**
     * Principal Name으로 세션을 검색합니다.
     * <p>
     * 저장된 모든 세션을 순회하며 {@link #PRINCIPAL_NAME_INDEX_NAME} 속성이
     * 주어진 principalName과 일치하는 세션들을 반환합니다.
     * </p>
     *
     * @param principalName 검색할 Principal Name (사용자 ID)
     * @return 해당 사용자의 모든 세션 (세션 ID -> MapSession)
     */
    @Override
    public Map<String, MapSession> findByIndexNameAndIndexValue(String indexName, String indexValue) {
        if (!PRINCIPAL_NAME_INDEX_NAME.equals(indexName)) {
            return Map.of();
        }
        return findByPrincipalName(indexValue);
    }

    /**
     * Principal Name으로 세션을 검색합니다.
     *
     * @param principalName 검색할 Principal Name
     * @return 해당 사용자의 모든 유효한 세션 맵
     */
    public Map<String, MapSession> findByPrincipalName(String principalName) {
        // 만료된 세션 정리
        cleanExpiredSessions();

        return this.sessions.entrySet().stream()
            .filter(entry -> {
                MapSession session = entry.getValue();
                String sessionPrincipal = session.getAttribute(PRINCIPAL_NAME_INDEX_NAME);
                return principalName.equals(sessionPrincipal);
            })
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                entry -> new MapSession(entry.getValue())
            ));
    }

    /**
     * 용량 상한으로 인해 fail-closed 처리된 누적 횟수를 반환합니다(외부 메트릭 연동용).
     */
    public long getCapacityRejectionCount() {
        return capacityRejectionCount.get();
    }

    /**
     * 스케줄러에서 호출되는 정리 작업 래퍼입니다. 정리 중 예외가 발생해도
     * 스케줄러 자체가 죽지 않도록 예외를 흡수하고 로그만 남깁니다.
     */
    private void cleanExpiredSessionsSafely() {
        try {
            cleanExpiredSessions();
        } catch (Exception ex) {
            log.warn("Keycloak Session: 만료 세션 정리 중 오류가 발생했습니다.", ex);
        }
    }

    /**
     * 만료된 세션들을 정리합니다.
     */
    private void cleanExpiredSessions() {
        Set<String> expiredSessionIds = this.sessions.entrySet().stream()
            .filter(entry -> entry.getValue().isExpired())
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());

        expiredSessionIds.forEach(this.sessions::remove);

        if (!expiredSessionIds.isEmpty()) {
            log.debug("Keycloak Session: 만료된 세션 {}개를 정리했습니다. (현재 {}개)",
                expiredSessionIds.size(), this.sessions.size());
        }
    }

    /**
     * 용량 상한 도달로 인한 fail-closed 거부 발생을 기록합니다.
     * <p>
     * 공격 볼륨만큼 매 요청마다 {@code warn} 로그가 찍히면 로그 자체가 2차 DoS 벡터가 되므로,
     * 최초 발생 시 즉시 로그를 남기고 이후에는 {@link #CAPACITY_WARN_LOG_INTERVAL_MS} 주기로
     * 요약만 기록합니다. 누적 발생 횟수는 {@link #getCapacityRejectionCount()}로 외부 메트릭
     * 수집기에 노출할 수 있습니다.
     * </p>
     */
    private void recordCapacitySaturated(String rejectedSessionId) {
        capacityRejectionCount.incrementAndGet();
        intervalRejectionCount.incrementAndGet();
        long now = System.currentTimeMillis();
        long last = lastCapacityWarnLogEpochMs.get();
        if (now - last >= CAPACITY_WARN_LOG_INTERVAL_MS
            && lastCapacityWarnLogEpochMs.compareAndSet(last, now)) {
            long summarized = intervalRejectionCount.getAndSet(0);
            log.warn("Keycloak Session: 저장소 용량 상한({})에 도달하여 최근 {}초간 신규 세션 {}회를 "
                    + "거부 처리했습니다(누적 {}회, 최근 거부 sessionId={}). 로그 폭주 방지를 위해 주기 요약만 기록합니다.",
                maxSessions, CAPACITY_WARN_LOG_INTERVAL_MS / 1000, summarized,
                capacityRejectionCount.get(), rejectedSessionId);
        }
    }

    /**
     * 세션 정리 스케줄러를 종료합니다. Spring 컨테이너가 빈 소멸 시 자동 호출합니다.
     */
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
}
