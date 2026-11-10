package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;

/**
 * V3-13 세션 이벤트 (#89): 실제 Keycloak으로 로그인·갱신·로그아웃하고, 샘플 앱이 Spring 이벤트로 받은 순서를 본다 (EVT-01).
 * 감사 로그 내용은 각 기능의 E2E가, 로그에 토큰·sid가 없는지는 {@link E2eZzLogHygieneTest}(EVT-02)가 본다.
 */
@E2eTest
class E2eSessionEventsTest {

    private static final String API_HOST = "api.kss.test";

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);
    private final SampleApps.Running app = SampleApps.demo();

    @Test
    @DisplayName("EVT-01 로그인 → 갱신 → 로그아웃: 이 세션의 이벤트가 CREATED, REFRESHED, ENDED(logout) 차례로 온다. 응답마다 X-Request-Id")
    void evt01() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = browser.cookie(API_HOST, "__Host-demo_sid").orElseThrow().value();
            UUID sessionId = UUID.fromString(String.valueOf(AppSessions.rowBySid(app, sid).get("id")));

            browser.removeCookie(API_HOST, "__Host-demo_at");
            Exchange me = browser.get(app.url("/api/me"));
            assertThat(me.status()).isEqualTo(200);
            assertThat(me.header("X-Request-Id")).as("EVT-03 응답에 요청 id").isPresent();

            Exchange csrf = browser.get(app.url("/api/csrf"));
            String token = AppSessions.json(csrf.body()).get("token").asString();
            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), new BasicHeader("Origin", BrowserClient.FRONTEND_ORIGIN),
                new BasicHeader("X-XSRF-TOKEN", token));
            assertThat(logout.status()).isEqualTo(302);

            List<KeycloakSessionEvent> events = app.sessionEvents().of(sessionId);
            assertThat(events).extracting(KeycloakSessionEvent::type)
                .containsExactly(KeycloakSessionEvent.Type.CREATED, KeycloakSessionEvent.Type.REFRESHED, KeycloakSessionEvent.Type.ENDED);
            assertThat(events.get(2).endReason()).isEqualTo(KeycloakSessionEndReason.LOGOUT);
            assertThat(events).allSatisfy(e -> assertThat(e.keycloakUserId()).isEqualTo(admin.userId("alice")));
            assertThat(events).extracting(KeycloakSessionEvent::occurredAt).isSorted();
        }
    }
}
