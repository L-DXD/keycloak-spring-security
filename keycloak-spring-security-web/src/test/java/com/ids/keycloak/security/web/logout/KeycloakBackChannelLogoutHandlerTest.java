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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.SessionIds;

class KeycloakBackChannelLogoutHandlerTest {

    static final Instant NOW = Instant.parse("2026-11-10T01:00:00Z");

    final InMemoryKeycloakSessionStore store = new InMemoryKeycloakSessionStore();
    final List<KeycloakSessionEvent> events = new ArrayList<>();
    final KeycloakBackChannelLogoutHandler handler = new KeycloakBackChannelLogoutHandler(store, events::add, Clock.fixed(NOW, ZoneOffset.UTC));

    void row(String kcSid) {
        store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(SessionIds.newSid()), "user-1", kcSid,
            new EncryptedToken("k1", new byte[] {1, 2, 3}), NOW.plusSeconds(1800), NOW, NOW.plusSeconds(3600), null));
    }

    static OidcLogoutToken token(String sid) {
        OidcLogoutToken.Builder builder = OidcLogoutToken.withTokenValue("logout-token").issuer("https://sso.example.com/realms/demo")
            .audience(List.of("demo")).subject("user-1").issuedAt(NOW).jti("jti-1")
            .events(Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));
        if (sid != null) {
            builder.sessionId(sid);
        }
        return builder.build();
    }

    MockHttpServletResponse send(OidcLogoutToken token) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.logout(new MockHttpServletRequest("POST", "/logout/connect/back-channel/keycloak"), response,
            new TestingAuthenticationToken(token, null));
        return response;
    }

    @Test
    @DisplayName("BCL-01 sid가 같은 행을 모두 지우고 행마다 ENDED(backchannel_logout). 다른 sid의 행은 그대로. 쿠키는 건드리지 않는다")
    void deletesBySid() {
        row("kc-sid-1");
        row("kc-sid-1");
        row("kc-sid-2");

        MockHttpServletResponse response = send(token("kc-sid-1"));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        assertThat(store.snapshot()).extracting(KeycloakSessionRecord::kcSid).containsExactly("kc-sid-2");
        assertThat(events).hasSize(2).allSatisfy(e -> assertThat(e.endReason()).isEqualTo(KeycloakSessionEndReason.BACKCHANNEL_LOGOUT));
    }

    @Test
    @DisplayName("BCL-03 행이 이미 없으면 200, 이벤트 없음")
    void noRow() {
        MockHttpServletResponse response = send(token("kc-sid-gone"));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("BCL-02 sid가 없는 토큰(사용자 전체 로그아웃)은 400 invalid_request, 행은 그대로")
    void noSid() throws Exception {
        row("kc-sid-1");

        MockHttpServletResponse response = send(token(null));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("\"error\":\"invalid_request\"").contains("sid");
        assertThat(store.snapshot()).hasSize(1);
        assertThat(events).isEmpty();
    }
}
