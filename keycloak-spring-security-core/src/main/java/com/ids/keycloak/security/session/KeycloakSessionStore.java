package com.ids.keycloak.security.session;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import com.ids.keycloak.security.crypto.EncryptedToken;

/**
 * 세션 행 저장소 (확장 지점). 기본 구현은 {@link JdbcKeycloakSessionStore}(PostgreSQL·H2)와 {@link InMemoryKeycloakSessionStore}.
 * <p>
 * 다른 DB나 테이블 구조를 쓰려면 이것을 구현해 빈으로 올린다. 두 기본 구현은 같은 계약 테스트를 통과한다 (STORE-06).
 */
public interface KeycloakSessionStore {

    /** 새 세션 행을 넣는다 (로그인). */
    void insert(KeycloakSessionRecord record);

    /** sid 해시로 찾는다. 끝난 행도 돌려준다 (판단은 부른 쪽이 한다). */
    Optional<KeycloakSessionRecord> findBySidHash(String sidHash);

    /**
     * 갱신용으로 행을 잠그고 {@code work}를 돌린다. {@code work}가 끝날 때까지 같은 행을 잠그려는 다른 호출은 기다린다 (STORE-04).
     * {@code work} 안에서 {@link #updateRefreshToken}·{@link #deleteBySidHash}를 불러도 된다 (같은 잠금 안).
     *
     * @param work 행(없으면 빈 값)을 받아 결과를 만든다
     */
    <T> T lockForRefresh(String sidHash, Function<Optional<KeycloakSessionRecord>, T> work);

    /** 갱신 결과를 적는다. */
    void updateRefreshToken(UUID id, EncryptedToken refreshToken, Instant refreshExpiresAt, Instant refreshedAt);

    /** sid 해시로 지운다 (로그아웃). 지운 행을 돌려준다. */
    Optional<KeycloakSessionRecord> deleteBySidHash(String sidHash);

    /** Keycloak 세션 id로 지운다 (back-channel 로그아웃). 지운 행들을 돌려준다. */
    List<KeycloakSessionRecord> deleteByKcSid(String kcSid);

    /**
     * 끝난 행(절대 상한 또는 리프레시 만료가 {@code now} 이전)을 최대 {@code limit}개 지운다 (STORE-05).
     *
     * @return 실제로 지운 행들. 여러 서버가 동시에 돌아도 한 행은 한 번만 돌려준다
     */
    List<KeycloakSessionRecord> deleteEnded(Instant now, int limit);
}
