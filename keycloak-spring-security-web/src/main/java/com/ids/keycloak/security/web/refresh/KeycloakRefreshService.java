package com.ids.keycloak.security.web.refresh;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;

import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.crypto.TokenDecryptionException;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.RefreshTokens;
import com.ids.keycloak.security.web.logout.KeycloakRefreshTokenRevoker;

/**
 * 갱신 (V3-09, 01 설계 4-2): 세션 행을 잠그고 Keycloak에서 새 토큰을 받는다. 같은 세션의 동시 요청은 잠금 순서대로 줄을 서고,
 * 먼저 갱신한 요청의 토큰을 {@code refresh-reuse-window} 동안 나눠 쓴다(Keycloak은 한 번만 부른다).
 * <ol>
 *   <li>행이 없다 → 끝 (사유 없음)</li>
 *   <li>절대 상한이 지났다 → 행 삭제, 사유 {@code absolute}. Keycloak을 부르지 않는다</li>
 *   <li>리프레시 토큰 만료(Client Session Idle)가 지났다 → 행 삭제, 사유 {@code idle}. Keycloak을 부르지 않는다</li>
 *   <li>이 인스턴스가 방금 갱신했다 → 그 토큰을 쓴다</li>
 *   <li>리프레시 토큰을 풀지 못한다 → 행 삭제, 사유 {@code decryption_failed}</li>
 *   <li>Keycloak이 {@code invalid_grant} → 행 삭제, 사유 {@code refresh_failed}. 부르지 못했으면 행을 두고 503</li>
 *   <li>새 액세스 토큰이 검증 규칙에 맞지 않거나 sub·sid가 행과 다르다 → 행 삭제, 사유 {@code invalid_token}</li>
 *   <li>행에 새 리프레시 토큰(활성 키로 암호화)과 갱신 시각을 쓰고 REFRESHED 이벤트</li>
 * </ol>
 * 갱신 중에는 DB 연결 하나로 행을 잠근 채 Keycloak을 부른다. 다른 인스턴스가 방금 갱신한 경우에는 한 번 더 갱신한다(드묾).
 * 옵션을 켜면 사유가 {@code absolute}·{@code invalid_token}일 때 잠금이 끝난 뒤 리프레시 토큰을 폐기한다(LOGOUT-06).
 */
public class KeycloakRefreshService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRefreshService.class);

    private final KeycloakSessionStore store;
    private final TokenCipher cipher;
    private final KeycloakTokenClient tokenClient;
    private final KeycloakAccessTokenValidator validator;
    private final KeycloakSessionEventPublisher events;
    private final Clock clock;
    private final Duration reuseWindow;
    private final KeycloakRefreshTokenRevoker revoker;

    /** 이 인스턴스가 방금 받은 토큰 (sid 해시 → 토큰). reuse-window가 지나면 버린다. */
    private final Map<String, Recent> recent = new ConcurrentHashMap<>();

    private record Recent(String accessToken, Instant refreshedAt) {
    }

    /** 잠금 안에서 정한 것. 이벤트와 토큰 폐기는 잠금(트랜잭션)이 끝난 뒤에 한다. */
    private record Outcome(KeycloakRefreshResult result, KeycloakSessionEvent event, Runnable afterLock) {

        Outcome(KeycloakRefreshResult result, KeycloakSessionEvent event) {
            this(result, event, null);
        }
    }

    public KeycloakRefreshService(KeycloakSessionStore store, TokenCipher cipher, KeycloakTokenClient tokenClient,
                                  KeycloakAccessTokenValidator validator, KeycloakSessionEventPublisher events, Clock clock,
                                  Duration reuseWindow, KeycloakRefreshTokenRevoker revoker) {
        this.store = Objects.requireNonNull(store);
        this.cipher = Objects.requireNonNull(cipher);
        this.tokenClient = Objects.requireNonNull(tokenClient);
        this.validator = Objects.requireNonNull(validator);
        this.events = Objects.requireNonNull(events);
        this.clock = Objects.requireNonNull(clock);
        this.reuseWindow = Objects.requireNonNull(reuseWindow);
        this.revoker = Objects.requireNonNull(revoker);
    }

    /** sid 쿠키 값으로 갱신한다. */
    public KeycloakRefreshResult refresh(String sid) {
        String sidHash = SessionIds.hash(sid);
        Outcome outcome = store.lockForRefresh(sidHash, row -> row.map(this::refreshLocked)
            .orElseGet(() -> new Outcome(KeycloakRefreshResult.sessionEnded(null), null)));
        if (outcome.event() != null) {
            events.publish(outcome.event());
        }
        if (outcome.afterLock() != null) {
            outcome.afterLock().run();
        }
        return outcome.result();
    }

    private Outcome refreshLocked(KeycloakSessionRecord row) {
        Instant now = clock.instant();
        if (row.isAbsolutelyExpired(now)) {
            return end(row, KeycloakSessionEndReason.ABSOLUTE_TIMEOUT, now, () -> revoker.revoke(row));
        }
        if (row.isRefreshExpired(now)) {
            return end(row, KeycloakSessionEndReason.IDLE, now);
        }
        Optional<Jwt> reusable = reusable(row, now);
        if (reusable.isPresent()) {
            log.debug("[KSS] 방금 갱신한 토큰을 씁니다 session={}", row.id());
            return new Outcome(KeycloakRefreshResult.reused(reusable.get(), cookieAge(reusable.get(), row, now)), null);
        }

        String refreshToken;
        try {
            refreshToken = cipher.decrypt(row.refreshToken());
        } catch (TokenDecryptionException e) {
            log.warn("[KSS] 리프레시 토큰을 풀지 못해 세션을 끝냅니다 session={} ({})", row.id(), e.getMessage());
            return end(row, KeycloakSessionEndReason.DECRYPTION_FAILED, now);
        }

        KeycloakTokenResponse tokens;
        try {
            tokens = tokenClient.refresh(refreshToken);
        } catch (KeycloakTokenException e) {
            if (e.isInvalidGrant()) {
                log.info("[KSS] Keycloak이 갱신을 거절해 세션을 끝냅니다 session={} ({})", row.id(), e.getMessage());
                return end(row, KeycloakSessionEndReason.REFRESH_FAILED, now);
            }
            log.warn("[KSS] Keycloak을 부르지 못해 갱신하지 못했습니다. 세션은 둡니다 session={} ({})", row.id(), e.getMessage());
            return new Outcome(KeycloakRefreshResult.unavailable(), null);
        }

        String newRefreshToken = tokens.refreshToken() != null ? tokens.refreshToken() : refreshToken;
        Instant refreshExpiresAt = refreshExpiresAt(newRefreshToken, tokens, row);
        AccessTokenValidationResult result = validator.validate(tokens.accessToken());
        if (result.status() == AccessTokenValidationResult.Status.UNAVAILABLE) {
            // 리프레시 토큰은 바뀌었을 수 있으니(회전) 저장하고, 이 요청만 503
            store.updateRefreshToken(row.id(), cipher.encrypt(newRefreshToken), refreshExpiresAt, row.refreshedAt());
            log.warn("[KSS] 갱신한 토큰을 검증할 서명 키를 받지 못했습니다 session={} ({})", row.id(), result.reason());
            return new Outcome(KeycloakRefreshResult.unavailable(), null);
        }
        if (!result.isValid() || !row.keycloakUserId().equals(result.subject()) || !row.kcSid().equals(result.sessionId())) {
            log.warn("[KSS] 갱신으로 받은 토큰이 세션과 맞지 않아 세션을 끝냅니다 session={} ({})", row.id(),
                result.isValid() ? "sub 또는 sid가 다름" : result.reason());
            return end(row, KeycloakSessionEndReason.INVALID_TOKEN, now, () -> revoker.revoke(row, newRefreshToken));
        }

        Instant refreshedAt = now.truncatedTo(ChronoUnit.MILLIS);
        store.updateRefreshToken(row.id(), cipher.encrypt(newRefreshToken), refreshExpiresAt, refreshedAt);
        remember(row.sidHash(), tokens.accessToken(), refreshedAt, now);
        return new Outcome(KeycloakRefreshResult.refreshed(result.jwt(), cookieAge(result.jwt(), row, now)),
            KeycloakSessionEvent.refreshed(row, now));
    }

    /** 행을 지우고 ENDED 이벤트를 준비한다 (잠금 안이라 같은 트랜잭션에서 지운다). */
    private Outcome end(KeycloakSessionRecord row, KeycloakSessionEndReason reason, Instant now) {
        return end(row, reason, now, null);
    }

    private Outcome end(KeycloakSessionRecord row, KeycloakSessionEndReason reason, Instant now, Runnable afterLock) {
        store.deleteBySidHash(row.sidHash());
        recent.remove(row.sidHash());
        return new Outcome(KeycloakRefreshResult.sessionEnded(reason), KeycloakSessionEvent.ended(row, reason, now), afterLock);
    }

    /** 이 인스턴스가 방금(reuse-window 안) 이 행을 갱신했고, 그 뒤로 다른 곳에서 갱신하지 않았으면 그 토큰. */
    private Optional<Jwt> reusable(KeycloakSessionRecord row, Instant now) {
        Recent last = recent.get(row.sidHash());
        if (last == null || row.refreshedAt() == null || !last.refreshedAt().equals(row.refreshedAt().truncatedTo(ChronoUnit.MILLIS))
            || !now.isBefore(last.refreshedAt().plus(reuseWindow))) {
            return Optional.empty();
        }
        AccessTokenValidationResult result = validator.validate(last.accessToken());
        return result.isValid() ? Optional.of(result.jwt()) : Optional.empty();
    }

    private void remember(String sidHash, String accessToken, Instant refreshedAt, Instant now) {
        recent.values().removeIf(r -> !now.isBefore(r.refreshedAt().plus(reuseWindow)));
        recent.put(sidHash, new Recent(accessToken, refreshedAt));
    }

    /** 새 리프레시 토큰 만료: 토큰의 exp → 응답의 refresh_expires_in → 예전 값. 절대 상한을 넘지 않는다. */
    protected Instant refreshExpiresAt(String refreshToken, KeycloakTokenResponse tokens, KeycloakSessionRecord row) {
        Instant expiresAt = RefreshTokens.expiresAt(refreshToken)
            .orElse(tokens.refreshExpiresAt() != null ? tokens.refreshExpiresAt() : row.refreshExpiresAt());
        return expiresAt.isAfter(row.absoluteExpiresAt()) ? row.absoluteExpiresAt() : expiresAt;
    }

    private static Duration cookieAge(Jwt accessToken, KeycloakSessionRecord row, Instant now) {
        Duration untilAbsolute = Duration.between(now, row.absoluteExpiresAt());
        if (accessToken.getExpiresAt() == null) {
            return untilAbsolute;
        }
        Duration untilExpiry = Duration.between(now, accessToken.getExpiresAt());
        return untilExpiry.compareTo(untilAbsolute) < 0 ? untilExpiry : untilAbsolute;
    }
}
