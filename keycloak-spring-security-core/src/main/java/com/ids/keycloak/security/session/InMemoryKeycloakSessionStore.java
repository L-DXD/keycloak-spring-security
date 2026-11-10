package com.ids.keycloak.security.session;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

import com.ids.keycloak.security.crypto.EncryptedToken;

/**
 * 서버 메모리 세션 저장소 ({@code session.store=memory}). 서버 한 대짜리 개발·테스트용이다.
 * 재시작하면 모두 로그아웃되고, 서버를 여러 대 띄우면 서로의 로그인이 보이지 않는다.
 */
public class InMemoryKeycloakSessionStore implements KeycloakSessionStore {

    private static final int LOCK_STRIPES = 64;

    private final Map<String, KeycloakSessionRecord> bySidHash = new ConcurrentHashMap<>();
    private final ReentrantLock[] locks = new ReentrantLock[LOCK_STRIPES];

    public InMemoryKeycloakSessionStore() {
        for (int i = 0; i < LOCK_STRIPES; i++) {
            locks[i] = new ReentrantLock();
        }
    }

    @Override
    public void insert(KeycloakSessionRecord record) {
        if (bySidHash.putIfAbsent(record.sidHash(), record) != null) {
            throw new IllegalStateException("같은 sid 해시의 세션이 이미 있다");
        }
    }

    @Override
    public Optional<KeycloakSessionRecord> findBySidHash(String sidHash) {
        return Optional.ofNullable(bySidHash.get(sidHash));
    }

    @Override
    public <T> T lockForRefresh(String sidHash, Function<Optional<KeycloakSessionRecord>, T> work) {
        ReentrantLock lock = locks[Math.floorMod(sidHash.hashCode(), LOCK_STRIPES)];
        lock.lock();
        try {
            return work.apply(findBySidHash(sidHash));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void updateRefreshToken(UUID id, EncryptedToken refreshToken, Instant refreshExpiresAt, Instant refreshedAt) {
        bySidHash.replaceAll((hash, record) -> record.id().equals(id) ? record.withRefresh(refreshToken, refreshExpiresAt, refreshedAt) : record);
    }

    @Override
    public Optional<KeycloakSessionRecord> deleteBySidHash(String sidHash) {
        return Optional.ofNullable(bySidHash.remove(sidHash));
    }

    @Override
    public List<KeycloakSessionRecord> deleteByKcSid(String kcSid) {
        List<KeycloakSessionRecord> deleted = new ArrayList<>();
        for (KeycloakSessionRecord record : List.copyOf(bySidHash.values())) {
            if (record.kcSid().equals(kcSid) && bySidHash.remove(record.sidHash(), record)) {
                deleted.add(record);
            }
        }
        return deleted;
    }

    @Override
    public List<KeycloakSessionRecord> deleteEnded(Instant now, int limit) {
        List<KeycloakSessionRecord> deleted = new ArrayList<>();
        for (KeycloakSessionRecord record : List.copyOf(bySidHash.values())) {
            if (deleted.size() >= limit) {
                break;
            }
            if (record.isEnded(now) && bySidHash.remove(record.sidHash(), record)) {
                deleted.add(record);
            }
        }
        return deleted;
    }

    /** 지금 들고 있는 행들 (테스트·점검용). */
    public List<KeycloakSessionRecord> snapshot() {
        return List.copyOf(bySidHash.values());
    }
}
