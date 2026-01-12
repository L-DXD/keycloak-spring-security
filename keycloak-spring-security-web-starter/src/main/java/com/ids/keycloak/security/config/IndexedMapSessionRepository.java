package com.ids.keycloak.security.config;

import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * {@link FindByIndexNameSessionRepository}를 구현하는 인-메모리 세션 저장소입니다.
 * <p>
 * Principal Name(사용자 ID)을 기준으로 세션을 검색할 수 있어,
 * 백채널 로그아웃 시 특정 사용자의 모든 세션을 조회하고 삭제할 수 있습니다.
 * </p>
 */
public class IndexedMapSessionRepository implements FindByIndexNameSessionRepository<MapSession> {

    /**
     * Principal Name을 저장하기 위한 세션 속성 키.
     * Spring Security는 이 키에 인증된 사용자의 이름을 저장합니다.
     */
    public static final String PRINCIPAL_NAME_INDEX_NAME = FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

    private final Map<String, MapSession> sessions;
    private Duration defaultMaxInactiveInterval;

    public IndexedMapSessionRepository() {
        this(new ConcurrentHashMap<>());
    }

    public IndexedMapSessionRepository(Map<String, MapSession> sessions) {
        this.sessions = sessions;
        this.defaultMaxInactiveInterval = Duration.ofMinutes(30);
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
        this.sessions.put(session.getId(), new MapSession(session));
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
     * 만료된 세션들을 정리합니다.
     */
    private void cleanExpiredSessions() {
        Set<String> expiredSessionIds = this.sessions.entrySet().stream()
            .filter(entry -> entry.getValue().isExpired())
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());

        expiredSessionIds.forEach(this.sessions::remove);
    }
}
