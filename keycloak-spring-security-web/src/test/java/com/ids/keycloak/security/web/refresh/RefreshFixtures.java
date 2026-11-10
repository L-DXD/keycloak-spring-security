package com.ids.keycloak.security.web.refresh;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.springframework.security.oauth2.jwt.Jwt;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;

/** 갱신 테스트 공용: 움직이는 시계, 가짜 Keycloak 토큰 주소, 가짜 검증기. */
final class RefreshFixtures {

    static final Instant LOGIN = Instant.parse("2026-11-10T03:00:00Z");
    static final KeycloakKeyRing KEYS = new KeycloakKeyRing("k1", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes()));

    private RefreshFixtures() {
    }

    /** 테스트가 앞으로 돌리는 시계. */
    static final class MovingClock extends Clock {
        final AtomicReference<Instant> now = new AtomicReference<>(LOGIN);

        void advanceSeconds(long seconds) {
            now.updateAndGet(i -> i.plusSeconds(seconds));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    /** 가짜 Keycloak: 부른 횟수를 세고, 정한 대로 답한다. */
    static final class FakeTokenClient implements KeycloakTokenClient {
        final AtomicInteger calls = new AtomicInteger();
        final List<String> receivedRefreshTokens = new ArrayList<>();
        volatile Function<String, KeycloakTokenResponse> answer;
        volatile long delayMillis;

        FakeTokenClient(Function<String, KeycloakTokenResponse> answer) {
            this.answer = answer;
        }

        @Override
        public KeycloakTokenResponse refresh(String refreshToken) {
            int n = calls.incrementAndGet();
            synchronized (receivedRefreshTokens) {
                receivedRefreshTokens.add(refreshToken);
            }
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            KeycloakTokenResponse response = answer.apply(refreshToken);
            return response == null ? new KeycloakTokenResponse("at-" + n, "rt-" + n, null) : response;
        }
    }

    /** 가짜 검증기: 토큰 문자열 → 결과. 정하지 않은 토큰은 sub user-1·sid kc-sid-1로 통과(만료는 시계 + 60초). */
    static final class FakeValidator implements KeycloakAccessTokenValidator {
        final Map<String, AccessTokenValidationResult> results = new HashMap<>();
        final Clock clock;

        FakeValidator(Clock clock) {
            this.clock = clock;
        }

        @Override
        public synchronized AccessTokenValidationResult validate(String token) {
            return results.getOrDefault(token, AccessTokenValidationResult.valid(jwt(token, "user-1", "kc-sid-1", clock.instant())));
        }
    }

    static Jwt jwt(String value, String sub, String sid, Instant issuedAt) {
        return Jwt.withTokenValue(value).header("alg", "RS256").subject(sub).claim("sid", sid).claim("azp", "demo")
            .issuedAt(issuedAt).expiresAt(issuedAt.plusSeconds(60)).build();
    }

    /** 로그인 때 만든 것 같은 행 (리프레시 토큰 rt-login, 리프레시 만료 30분, 절대 상한 12시간). sid 원문을 돌려준다. */
    static String loggedIn(KeycloakSessionStore store, AesGcmTokenCipher cipher) {
        return loggedIn(store, cipher, Duration.ofHours(12));
    }

    /** 절대 상한을 정해 로그인 행을 넣는다. 리프레시 만료는 30분(상한보다 길면 상한). */
    static String loggedIn(KeycloakSessionStore store, AesGcmTokenCipher cipher, Duration absolute) {
        String sid = SessionIds.newSid();
        Instant absoluteAt = LOGIN.plus(absolute);
        Instant refreshAt = LOGIN.plusSeconds(1800).isAfter(absoluteAt) ? absoluteAt : LOGIN.plusSeconds(1800);
        store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "user-1", "kc-sid-1", cipher.encrypt("rt-login"),
            refreshAt, LOGIN, absoluteAt, null));
        return sid;
    }

    static List<KeycloakSessionEvent> events() {
        return java.util.Collections.synchronizedList(new ArrayList<>());
    }
}
