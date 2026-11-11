package com.ids.keycloak.security.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import com.ids.keycloak.security.crypto.EncryptedToken;

/**
 * 세션 행 하나 ({@code auth_session}, 01 설계 5-1). sid 원문과 리프레시 토큰 원문은 들고 있지 않다 (STORE-01).
 *
 * @param id                행 id
 * @param sidHash           sid 쿠키 값의 SHA-256 (hex 64자)
 * @param keycloakUserId    액세스 토큰 sub
 * @param kcSid             액세스 토큰 sid (back-channel 로그아웃용)
 * @param refreshToken      암호화한 리프레시 토큰과 키 id
 * @param refreshExpiresAt  리프레시 토큰 만료
 * @param createdAt         로그인 시각
 * @param absoluteExpiresAt 절대 상한 (로그인 + absolute-timeout)
 * @param refreshedAt       마지막 갱신 시각. 갱신한 적 없으면 {@code null}
 */
public record KeycloakSessionRecord(UUID id, String sidHash, String keycloakUserId, String kcSid, EncryptedToken refreshToken,
                                    Instant refreshExpiresAt, Instant createdAt, Instant absoluteExpiresAt, Instant refreshedAt) {

    public KeycloakSessionRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(sidHash, "sidHash");
        Objects.requireNonNull(keycloakUserId, "keycloakUserId");
        Objects.requireNonNull(kcSid, "kcSid");
        Objects.requireNonNull(refreshToken, "refreshToken");
        Objects.requireNonNull(refreshExpiresAt, "refreshExpiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
    }

    /** 절대 상한이 지났는가. */
    public boolean isAbsolutelyExpired(Instant now) {
        return !now.isBefore(absoluteExpiresAt);
    }

    /** 리프레시 토큰이 만료됐는가. */
    public boolean isRefreshExpired(Instant now) {
        return !now.isBefore(refreshExpiresAt);
    }

    /** 끝난 세션인가 (절대 상한 또는 리프레시 만료). */
    public boolean isEnded(Instant now) {
        return isAbsolutelyExpired(now) || isRefreshExpired(now);
    }

    /** 갱신 결과를 담은 새 행. */
    public KeycloakSessionRecord withRefresh(EncryptedToken newRefreshToken, Instant newRefreshExpiresAt, Instant refreshedAt) {
        return new KeycloakSessionRecord(id, sidHash, keycloakUserId, kcSid, newRefreshToken, newRefreshExpiresAt, createdAt,
            absoluteExpiresAt, refreshedAt);
    }

    @Override
    public String toString() {
        return "KeycloakSessionRecord[id=" + id + ", user=" + keycloakUserId + ", absoluteExpiresAt=" + absoluteExpiresAt + "]";
    }
}
