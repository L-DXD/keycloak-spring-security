package com.ids.keycloak.security.web.logout;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;
import com.ids.keycloak.security.web.logout.KeycloakLogoutHandler.Result;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenException;
import com.ids.keycloak.security.web.refresh.KeycloakTokenResponse;

import jakarta.servlet.http.Cookie;

class KeycloakLogoutHandlerTest {

    static final Instant NOW = Instant.parse("2026-11-10T01:00:00Z");

    final InMemoryKeycloakSessionStore store = new InMemoryKeycloakSessionStore();
    final AesGcmTokenCipher cipher = new AesGcmTokenCipher(new KeycloakKeyRing("k1", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes())));
    final List<KeycloakSessionEvent> events = new ArrayList<>();
    final List<String> loggedOut = new ArrayList<>();
    RuntimeException keycloakFailure;
    final KeycloakTokenClient keycloak = new KeycloakTokenClient() {
        @Override
        public KeycloakTokenResponse refresh(String refreshToken) {
            throw new AssertionError("로그아웃은 갱신하지 않는다");
        }

        @Override
        public void logout(String refreshToken) {
            if (keycloakFailure != null) {
                throw keycloakFailure;
            }
            loggedOut.add(refreshToken);
        }

        @Override
        public void revoke(String refreshToken) {
            throw new AssertionError("로그아웃은 폐기를 따로 부르지 않는다");
        }
    };
    final KeycloakLogoutHandler handler = new KeycloakLogoutHandler(store, cipher, keycloak, new DefaultKeycloakCookieWriter("demo"),
        events::add, Clock.fixed(NOW, ZoneOffset.UTC));

    String loggedIn() {
        String sid = SessionIds.newSid();
        store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "user-1", "kc-sid-1", cipher.encrypt("rt-row"),
            NOW.plusSeconds(1800), NOW, NOW.plusSeconds(3600), null));
        return sid;
    }

    record Outcome(Result result, MockHttpServletResponse response) {
    }

    Outcome logout(Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.logout(request, response, null);
        return new Outcome(KeycloakLogoutHandler.result(request), response);
    }

    @Test
    @DisplayName("LOGOUT-01 행을 지우고(ENDED logout) 쿠키 4개를 지운 뒤, 행의 리프레시 토큰으로 Keycloak 로그아웃을 부른다")
    void logsOutAtKeycloak() {
        String sid = loggedIn();

        Outcome outcome = logout(new Cookie("__Host-demo_sid", sid));

        assertThat(outcome.result()).isEqualTo(Result.KEYCLOAK_LOGGED_OUT);
        assertThat(loggedOut).containsExactly("rt-row");
        assertThat(store.snapshot()).isEmpty();
        assertThat(outcome.response().getHeaders("Set-Cookie")).hasSize(4).allMatch(c -> c.contains("Max-Age=0"));
        assertThat(events).singleElement().satisfies(e -> assertThat(e.endReason()).isEqualTo(KeycloakSessionEndReason.LOGOUT));
    }

    @Test
    @DisplayName("LOGOUT-02 Keycloak이 거절하거나 닿지 않아도 행·쿠키는 지우고, 결과는 KEYCLOAK_FAILED (OIDC 로그아웃 주소로)")
    void keycloakFailureStillEndsLocally() {
        String sid = loggedIn();
        keycloakFailure = new KeycloakTokenException("invalid_grant", "Session not active", null);

        Outcome outcome = logout(new Cookie("__Host-demo_sid", sid));

        assertThat(outcome.result()).isEqualTo(Result.KEYCLOAK_FAILED);
        assertThat(store.snapshot()).isEmpty();
        assertThat(outcome.response().getHeaders("Set-Cookie")).hasSize(4);
        assertThat(events).hasSize(1);
    }

    @Test
    @DisplayName("LOGOUT-05 쿠키가 없거나 행이 없으면 Keycloak을 부르지 않고 NO_SESSION (쿠키는 지운다)")
    void noSession() {
        assertThat(logout().result()).isEqualTo(Result.NO_SESSION);
        Outcome stale = logout(new Cookie("__Host-demo_sid", SessionIds.newSid()));
        assertThat(stale.result()).isEqualTo(Result.NO_SESSION);
        assertThat(stale.response().getHeaders("Set-Cookie")).hasSize(4);
        assertThat(loggedOut).isEmpty();
        assertThat(events).isEmpty();
    }
}
