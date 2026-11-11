package com.ids.keycloak.security.web.refresh;

import static com.ids.keycloak.security.web.refresh.RefreshFixtures.KEYS;
import static com.ids.keycloak.security.web.refresh.RefreshFixtures.loggedIn;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.web.logout.KeycloakRefreshTokenRevoker;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshResult.Status;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.FakeTokenClient;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.FakeValidator;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.MovingClock;

class KeycloakRefreshServiceTest {

    final MovingClock clock = new MovingClock();
    final InMemoryKeycloakSessionStore store = new InMemoryKeycloakSessionStore();
    AesGcmTokenCipher cipher = new AesGcmTokenCipher(KEYS);
    final FakeTokenClient keycloak = new FakeTokenClient(rt -> null);
    final FakeValidator validator = new FakeValidator(clock);
    final List<KeycloakSessionEvent> events = RefreshFixtures.events();
    boolean revokeOnLocalLogout = false;

    KeycloakRefreshService service() {
        return new KeycloakRefreshService(store, cipher, keycloak, validator, events::add, clock, Duration.ofSeconds(10),
            new KeycloakRefreshTokenRevoker(revokeOnLocalLogout, cipher, keycloak));
    }

    KeycloakSessionRecord row(String sid) {
        return store.findBySidHash(SessionIds.hash(sid)).orElseThrow();
    }

    @Test
    @DisplayName("REFRESH-01 갱신하면 새 토큰이 나오고, 행의 리프레시 토큰 암호문과 갱신 시각이 바뀌고, REFRESHED 이벤트가 난다")
    void refreshes() {
        String sid = loggedIn(store, cipher);
        EncryptedToken before = row(sid).refreshToken();
        clock.advanceSeconds(90);

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.status()).isEqualTo(Status.REFRESHED);
        assertThat(result.accessToken().getTokenValue()).isEqualTo("at-1");
        assertThat(result.accessTokenCookieAge()).isEqualTo(Duration.ofSeconds(60));
        assertThat(keycloak.receivedRefreshTokens).containsExactly("rt-login");
        KeycloakSessionRecord after = row(sid);
        assertThat(after.refreshToken()).isNotEqualTo(before);
        assertThat(cipher.decrypt(after.refreshToken())).isEqualTo("rt-1");
        assertThat(after.refreshedAt()).isEqualTo(clock.instant());
        assertThat(events).singleElement().extracting(KeycloakSessionEvent::type).isEqualTo(KeycloakSessionEvent.Type.REFRESHED);
    }

    @Test
    @DisplayName("at 쿠키 수명은 절대 상한 남은 시간을 넘지 않는다")
    void cookieAgeCappedByAbsolute() {
        String sid = loggedIn(store, cipher, Duration.ofSeconds(50));
        clock.advanceSeconds(30);

        // 새 at는 60초짜리지만 절대 상한까지 20초 남았다
        assertThat(service().refresh(sid).accessTokenCookieAge()).isEqualTo(Duration.ofSeconds(20));
    }

    @Test
    @DisplayName("REFRESH-03 절대 상한이 지났으면 Keycloak을 부르지 않고 행을 지운다 (사유 absolute)")
    void absoluteTimeout() {
        String sid = loggedIn(store, cipher);
        clock.advanceSeconds(12 * 3600);

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.status()).isEqualTo(Status.SESSION_ENDED);
        assertThat(result.endReason()).isEqualTo(KeycloakSessionEndReason.ABSOLUTE_TIMEOUT);
        assertThat(keycloak.calls).hasValue(0);
        assertThat(store.snapshot()).isEmpty();
        assertThat(events).singleElement().extracting(KeycloakSessionEvent::endReason).isEqualTo(KeycloakSessionEndReason.ABSOLUTE_TIMEOUT);
    }

    @Test
    @DisplayName("REFRESH-05 리프레시 토큰 만료(Client Session Idle)가 지났으면 Keycloak을 부르지 않고 끝낸다 (사유 idle)")
    void idle() {
        String sid = loggedIn(store, cipher);
        clock.advanceSeconds(1800);

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.endReason()).isEqualTo(KeycloakSessionEndReason.IDLE);
        assertThat(keycloak.calls).hasValue(0);
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-04 Keycloak이 invalid_grant면 행을 지운다 (사유 refresh_failed)")
    void invalidGrant() {
        String sid = loggedIn(store, cipher);
        keycloak.answer = rt -> {
            throw new KeycloakTokenException("invalid_grant", "Session not active", null);
        };

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.endReason()).isEqualTo(KeycloakSessionEndReason.REFRESH_FAILED);
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-06 Keycloak을 부르지 못하면 503 대상, 행은 그대로")
    void keycloakUnavailable() {
        String sid = loggedIn(store, cipher);
        EncryptedToken before = row(sid).refreshToken();
        keycloak.answer = rt -> {
            throw new KeycloakTokenException("invalid_token_response", "Connection refused", null);
        };

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.status()).isEqualTo(Status.UNAVAILABLE);
        assertThat(row(sid).refreshToken()).isEqualTo(before);
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-08 갱신 응답 토큰의 sub가 행과 다르면 행을 지운다 (사유 invalid_token)")
    void subjectMismatch() {
        String sid = loggedIn(store, cipher);
        validator.results.put("at-1", AccessTokenValidationResult.valid(RefreshFixtures.jwt("at-1", "someone-else", "kc-sid-1", clock.instant())));

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.endReason()).isEqualTo(KeycloakSessionEndReason.INVALID_TOKEN);
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-08 갱신 응답 토큰의 sid가 행과 다르면 행을 지운다 (사유 invalid_token)")
    void sessionIdMismatch() {
        String sid = loggedIn(store, cipher);
        validator.results.put("at-1", AccessTokenValidationResult.valid(RefreshFixtures.jwt("at-1", "user-1", "kc-sid-other", clock.instant())));

        assertThat(service().refresh(sid).endReason()).isEqualTo(KeycloakSessionEndReason.INVALID_TOKEN);
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    @DisplayName("LOGOUT-06 옵션을 켜면 절대 상한으로 끝낸 세션의 리프레시 토큰을 폐기한다. 기본(끔)은 폐기하지 않는다")
    void revokeOnAbsoluteTimeout() {
        String sid = loggedIn(store, cipher);
        clock.advanceSeconds(12 * 3600);
        service().refresh(sid);
        assertThat(keycloak.revoked).as("기본은 끔").isEmpty();

        revokeOnLocalLogout = true;
        String sid2 = loggedIn(store, cipher);
        service().refresh(sid2);
        assertThat(keycloak.revoked).containsExactly("rt-login");
        assertThat(keycloak.calls).as("갱신은 부르지 않는다").hasValue(0);
    }

    @Test
    @DisplayName("LOGOUT-06 옵션을 켜면 갱신 응답 토큰이 맞지 않아 끝낸 세션은 새로 받은 리프레시 토큰을 폐기한다")
    void revokeNewRefreshTokenOnInvalidToken() {
        revokeOnLocalLogout = true;
        String sid = loggedIn(store, cipher);
        validator.results.put("at-1", AccessTokenValidationResult.invalid("aud가 다름"));

        service().refresh(sid);

        assertThat(keycloak.revoked).containsExactly("rt-1");
    }

    @Test
    @DisplayName("LOGOUT-06 옵션을 켜도 idle·Keycloak 거절로 끝낸 세션은 폐기하지 않는다 (Keycloak에서 이미 죽은 토큰)")
    void noRevokeWhenKeycloakAlreadyEnded() {
        revokeOnLocalLogout = true;
        String idle = loggedIn(store, cipher);
        clock.advanceSeconds(1801);
        service().refresh(idle);

        clock.reset();
        String rejected = loggedIn(store, cipher);
        keycloak.answer = rt -> {
            throw new KeycloakTokenException("invalid_grant", "Session not active", null);
        };
        service().refresh(rejected);

        assertThat(keycloak.revoked).isEmpty();
    }

    @Test
    @DisplayName("갱신 응답 토큰이 검증 규칙에 맞지 않으면 행을 지운다 (사유 invalid_token)")
    void refreshedTokenInvalid() {
        String sid = loggedIn(store, cipher);
        validator.results.put("at-1", AccessTokenValidationResult.invalid("aud가 다름"));

        assertThat(service().refresh(sid).endReason()).isEqualTo(KeycloakSessionEndReason.INVALID_TOKEN);
    }

    @Test
    @DisplayName("STORE-02 키 k1로 저장한 행은 활성 키가 k2로 바뀌어도 풀리고, 갱신 때 k2로 다시 저장된다")
    void keyRotation() {
        String sid = loggedIn(store, cipher);
        assertThat(row(sid).refreshToken().keyId()).isEqualTo("k1");
        cipher = new AesGcmTokenCipher(new KeycloakKeyRing("k2", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes(),
            "k2", "fedcba9876543210fedcba9876543210".getBytes())));

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.status()).isEqualTo(Status.REFRESHED);
        assertThat(keycloak.receivedRefreshTokens).containsExactly("rt-login");
        assertThat(row(sid).refreshToken().keyId()).isEqualTo("k2");
    }

    @Test
    @DisplayName("STORE-03 암호문 1바이트가 바뀌었으면 500이 아니라 로컬 로그아웃 (사유 decryption_failed)")
    void tamperedCiphertext() {
        String sid = loggedIn(store, cipher);
        KeycloakSessionRecord original = row(sid);
        byte[] bytes = original.refreshToken().ciphertext().clone();
        bytes[bytes.length / 2] ^= 0x01;
        store.deleteBySidHash(original.sidHash());
        store.insert(new KeycloakSessionRecord(original.id(), original.sidHash(), original.keycloakUserId(), original.kcSid(),
            new EncryptedToken("k1", bytes), original.refreshExpiresAt(), original.createdAt(), original.absoluteExpiresAt(), null));

        KeycloakRefreshResult result = service().refresh(sid);

        assertThat(result.endReason()).isEqualTo(KeycloakSessionEndReason.DECRYPTION_FAILED);
        assertThat(keycloak.calls).hasValue(0);
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-09 다른 요청이 5초 전에 갱신했으면 Keycloak을 다시 부르지 않고 그 토큰을 쓴다. 10초가 지나면 다시 갱신한다")
    void reusesRecentRefresh() {
        String sid = loggedIn(store, cipher);
        KeycloakRefreshService service = service();
        KeycloakRefreshResult first = service.refresh(sid);

        clock.advanceSeconds(5);
        KeycloakRefreshResult second = service.refresh(sid);

        assertThat(second.status()).isEqualTo(Status.REUSED);
        assertThat(second.accessToken().getTokenValue()).isEqualTo(first.accessToken().getTokenValue());
        assertThat(keycloak.calls).hasValue(1);

        clock.advanceSeconds(5);
        assertThat(service.refresh(sid).status()).isEqualTo(Status.REFRESHED);
        assertThat(keycloak.calls).hasValue(2);
        assertThat(keycloak.receivedRefreshTokens).containsExactly("rt-login", "rt-1");
    }

    @Test
    @DisplayName("다른 인스턴스가 그 뒤에 갱신했으면(행의 갱신 시각이 다름) 다시 갱신한다")
    void doesNotReuseWhenRowChangedElsewhere() {
        String sid = loggedIn(store, cipher);
        KeycloakRefreshService service = service();
        service.refresh(sid);
        clock.advanceSeconds(2);
        KeycloakSessionRecord row = row(sid);
        store.updateRefreshToken(row.id(), cipher.encrypt("rt-other-instance"), row.refreshExpiresAt(), clock.instant());

        assertThat(service.refresh(sid).status()).isEqualTo(Status.REFRESHED);
        assertThat(keycloak.receivedRefreshTokens).containsExactly("rt-login", "rt-other-instance");
    }

    @Test
    @DisplayName("Keycloak이 새 리프레시 토큰을 주지 않으면 예전 것을 계속 쓴다")
    void keepsRefreshTokenWhenNotRotated() {
        String sid = loggedIn(store, cipher);
        keycloak.answer = rt -> new KeycloakTokenResponse("at-x", null, null);

        service().refresh(sid);

        assertThat(cipher.decrypt(row(sid).refreshToken())).isEqualTo("rt-login");
    }

    @Test
    @DisplayName("행이 없으면 세션 끝 (사유 없음, 이벤트 없음)")
    void noRow() {
        KeycloakRefreshResult result = service().refresh(SessionIds.newSid());

        assertThat(result.status()).isEqualTo(Status.SESSION_ENDED);
        assertThat(result.endReason()).isNull();
        assertThat(events).isEmpty();
        assertThat(keycloak.calls).hasValue(0);
    }
}
