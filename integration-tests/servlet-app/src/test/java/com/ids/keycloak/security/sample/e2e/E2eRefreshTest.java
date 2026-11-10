package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenException;

import tools.jackson.databind.JsonNode;

/**
 * V3-09 갱신 (#85): 액세스 토큰이 만료되면 서버가 sid로 세션 행을 잠그고 Keycloak에서 새 토큰을 받는다.
 * 실제 Keycloak·PostgreSQL과 샘플 앱으로 REFRESH-01~07을 본다. REFRESH-08·09는 web 모듈 단위·통합 테스트가 본다.
 * <p>
 * 액세스 토큰 만료는 at 쿠키를 지워서 만든다(브라우저가 Max-Age가 지난 쿠키를 버린 것과 같다). 실제 60초 만료와
 * Client Session Idle(2분)은 {@code @Tag("slow")} 테스트 하나가 기다려서 본다.
 */
@E2eTest
class E2eRefreshTest {

    private static final String API_HOST = "api.kss.test";
    private static final String SID = "__Host-demo_sid";
    private static final String AT = "__Host-demo_at";
    private static final List<String> SESSION_COOKIES = List.of(SID, AT, "__Host-demo_csrf", "__Host-demo_login");
    private static final String AUDIT_LOGGER = "com.ids.keycloak.security.audit";

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);
    private final SampleApps.Running app = SampleApps.demo();

    @AfterEach
    void resetApp() {
        app.clock().reset();
        app.keycloakOutage().end();
    }

    @Test
    @DisplayName("REFRESH-01 at가 만료(쿠키 없음)된 뒤 GET /api/me → 200, 새 at 쿠키, 행의 refreshed_at·암호문이 바뀐다. 화면은 갱신을 모른다")
    void refresh01() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> before = AppSessions.rowBySid(app, sid);
            String refreshTokenBefore = AppSessions.refreshToken(app, sid);
            String kcSid = (String) before.get("kc_sid");
            int refreshes = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();
            browser.removeCookie(API_HOST, AT);

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).as("리다이렉트 없이 바로 200").isEqualTo(200);
            assertThat(AppSessions.json(me.body()).get("sub").asString()).isEqualTo(admin.userId("alice"));
            assertThat(me.setCookie(AT)).hasValueSatisfying(at -> {
                assertThat(at.raw()).contains("Secure").contains("HttpOnly").contains("Path=/").containsPattern("Max-Age=(5\\d|60)\\b");
                JsonNode claims = AppSessions.claims(at.value());
                assertThat(claims.get("sub").asString()).isEqualTo(admin.userId("alice"));
                assertThat(claims.get("sid").asString()).isEqualTo(kcSid);
            });
            assertThat(me.setCookie(SID)).as("sid 쿠키는 그대로").isEmpty();

            Map<String, Object> after = AppSessions.rowBySid(app, sid);
            assertThat(before.get("refreshed_at")).isNull();
            assertThat(AppSessions.instant(after.get("refreshed_at"))).isAfter(AppSessions.instant(after.get("created_at")));
            assertThat((byte[]) after.get("refresh_token_enc")).isNotEqualTo((byte[]) before.get("refresh_token_enc"));
            assertThat(AppSessions.refreshToken(app, sid)).as("Keycloak이 준 새 리프레시 토큰").isNotEqualTo(refreshTokenBefore);
            assertThat(after.get("id")).isEqualTo(before.get("id"));
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).hasSize(refreshes + 1);

            Exchange again = browser.get(app.url("/api/me"));
            assertThat(again.status()).isEqualTo(200);
            assertThat(again.headers("Set-Cookie")).as("새 at로 통과, 다시 갱신하지 않는다").isEmpty();
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).hasSize(refreshes + 1);
        }
    }

    @Test
    @DisplayName("REFRESH-02 만료 상태에서 같은 sid로 요청 5개를 동시에 → 모두 200, Keycloak 갱신 호출은 1번 (Keycloak 이벤트로 확인)")
    void refresh02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            String kcSid = (String) AppSessions.rowBySid(app, sid).get("kc_sid");
            int refreshes = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();
            browser.removeCookie(API_HOST, AT);

            List<Exchange> responses = browser.getConcurrently(app.url("/api/me"), 5);

            assertThat(responses).extracting(Exchange::status).containsOnly(200);
            assertThat(responses).allSatisfy(r -> assertThat(r.setCookie(AT)).isPresent());
            assertThat(responses.stream().map(r -> r.setCookie(AT).orElseThrow().value()).distinct())
                .as("먼저 갱신한 요청의 at를 나눠 쓴다").hasSize(1);
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).hasSize(refreshes + 1);
            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);
        }
    }

    @Test
    @DisplayName("REFRESH-03 절대 상한(테스트 3분)이 지난 뒤 요청 → Keycloak을 부르지 않고 401, 행·쿠키 삭제, 사유 absolute")
    void refresh03() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            String kcSid = (String) row.get("kc_sid");
            int refreshes = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();
            app.clock().advance(Duration.ofMinutes(3).plusSeconds(1));

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertThat(AppSessions.json(me.body()).get("code").asString()).isEqualTo("AUTHENTICATION_REQUIRED");
            assertSessionEnded(browser, me, sid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=absolute") && m.contains("session=" + row.get("id")));
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).as("Keycloak을 부르지 않는다").hasSize(refreshes);
        }
    }

    @Test
    @DisplayName("REFRESH-04 Keycloak에서 계정을 막은 뒤 at 만료 → Keycloak이 invalid_grant, 앱은 401, 행·쿠키 삭제, 사유 refresh_failed")
    void refresh04() throws Exception {
        String username = "refresh04-" + UUID.randomUUID().toString().substring(0, 8);
        String password = "temp-" + UUID.randomUUID();
        String userId = admin.createUser(username, password);
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, username, password);
            String sid = sid(browser);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            Object rowId = row.get("id");
            String kcSid = (String) row.get("kc_sid");
            admin.setUserEnabled(userId, false);
            browser.removeCookie(API_HOST, AT);

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertSessionEnded(browser, me, sid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=refresh_failed") && m.contains("session=" + rowId));
            assertThat(admin.sessionEvents("REFRESH_TOKEN_ERROR", kcSid))
                .as("Keycloak이 이 세션의 갱신을 거절했다")
                .anyMatch(e -> "User disabled".equals(e.path("details").path("reason").asString()));
        } finally {
            admin.deleteUser(userId);
        }
    }

    @Test
    @DisplayName("REFRESH-05 리프레시 토큰 만료(Client Session Idle 2분)가 지난 뒤 요청 → Keycloak을 부르지 않고 401, 사유 idle")
    void refresh05() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            String kcSid = (String) row.get("kc_sid");
            Instant createdAt = AppSessions.instant(row.get("created_at"));
            Instant refreshExpiresAt = AppSessions.instant(row.get("refresh_expires_at"));
            assertThat(Duration.between(createdAt, refreshExpiresAt))
                .as("리프레시 만료는 Keycloak이 준 값(Client Session Idle 2분)")
                .isBetween(Duration.ofSeconds(110), Duration.ofSeconds(121));
            int refreshes = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();
            app.clock().advance(Duration.between(Instant.now(), refreshExpiresAt).plusSeconds(1));

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertSessionEnded(browser, me, sid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=idle") && m.contains("session=" + row.get("id")));
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).hasSize(refreshes);
        }
    }

    @Test
    @Tag("slow")
    @DisplayName("REFRESH-01·05 (실제 시간) 65초 뒤 at가 실제로 만료돼도 200으로 갱신된다. 요청 없이 125초 지나면 Keycloak도 거절하고 앱은 401 idle")
    void realTimeExpiry() throws Exception {
        try (BrowserClient active = new BrowserClient(env.caCertificate());
             BrowserClient idle = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            active.login(app, "alice", "alice-test-password");
            idle.login(app, "bob", "bob-test-password");
            String idleSid = sid(idle);
            Object idleRowId = AppSessions.rowBySid(app, idleSid).get("id");

            Thread.sleep(65_000);
            assertThat(active.cookie(API_HOST, AT)).as("브라우저가 Max-Age가 지난 at 쿠키를 버렸다").isEmpty();
            Exchange refreshed = active.get(app.url("/api/me"));
            assertThat(refreshed.status()).isEqualTo(200);
            assertThat(refreshed.setCookie(AT)).isPresent();

            Thread.sleep(60_000);
            String idleRefreshToken = AppSessions.refreshToken(app, idleSid);
            assertThatThrownBy(() -> app.context().getBean(KeycloakTokenClient.class).refresh(idleRefreshToken))
                .as("Keycloak도 이 리프레시 토큰을 거절한다 (앱의 idle 판단과 같다)")
                .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isTrue());

            Exchange me = idle.get(app.url("/api/me"));
            assertThat(me.status()).isEqualTo(401);
            assertSessionEnded(idle, me, idleSid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=idle") && m.contains("session=" + idleRowId));
        }
    }

    @Test
    @DisplayName("REFRESH-06 갱신할 때 Keycloak에 닿지 않으면 503, 행·쿠키는 그대로. 다시 닿으면 다음 요청은 200")
    void refresh06() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> before = AppSessions.rowBySid(app, sid);
            browser.removeCookie(API_HOST, AT);
            app.keycloakOutage().begin();

            Exchange unavailable = browser.get(app.url("/api/me"));

            assertThat(unavailable.status()).isEqualTo(503);
            assertThat(AppSessions.json(unavailable.body()).get("code").asString()).isEqualTo("KEYCLOAK_UNAVAILABLE");
            assertThat(unavailable.headers("Set-Cookie")).as("쿠키를 지우지 않는다").isEmpty();
            Map<String, Object> during = AppSessions.rowBySid(app, sid);
            assertThat((byte[]) during.get("refresh_token_enc")).isEqualTo((byte[]) before.get("refresh_token_enc"));
            assertThat(during.get("refreshed_at")).isEqualTo(before.get("refreshed_at"));

            app.keycloakOutage().end();
            Exchange recovered = browser.get(app.url("/api/me"));

            assertThat(recovered.status()).isEqualTo(200);
            assertThat(recovered.setCookie(AT)).isPresent();
        }
    }

    @Test
    @DisplayName("REFRESH-07 만료 상태에서 X-Background: 1 요청 → 갱신하지 않고 401, 행·쿠키 그대로. 사용자가 부른 다음 요청은 갱신된다")
    void refresh07() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> before = AppSessions.rowBySid(app, sid);
            String kcSid = (String) before.get("kc_sid");
            int refreshes = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();
            browser.removeCookie(API_HOST, AT);

            Exchange background = browser.get(app.url("/api/me"), new BasicHeader("X-Background", "1"));

            assertThat(background.status()).isEqualTo(401);
            assertThat(background.headers("Set-Cookie")).isEmpty();
            assertThat(AppSessions.rowBySid(app, sid).get("refreshed_at")).isEqualTo(before.get("refreshed_at"));
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).hasSize(refreshes);

            Exchange user = browser.get(app.url("/api/me"));
            assertThat(user.status()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("STORE-03 (E2E) DB의 리프레시 토큰 암호문 1바이트를 바꾼 뒤 갱신 → 500이 아니라 401, 행·쿠키 삭제, 사유 decryption_failed")
    void store03TamperedCiphertext() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            byte[] ciphertext = (byte[]) row.get("refresh_token_enc");
            byte[] tampered = Arrays.copyOf(ciphertext, ciphertext.length);
            tampered[tampered.length / 2] ^= 0x01;
            AppSessions.jdbc(app).update("UPDATE auth_session SET refresh_token_enc = ? WHERE id = ?", tampered, row.get("id"));
            browser.removeCookie(API_HOST, AT);

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertSessionEnded(browser, me, sid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=decryption_failed") && m.contains("session=" + row.get("id")));
        }
    }

    private static String sid(BrowserClient browser) {
        return browser.cookie(API_HOST, SID).orElseThrow(() -> new AssertionError("sid 쿠키가 없다")).value();
    }

    /** 세션이 끝났다: 행 삭제, 쿠키 4개 Max-Age=0, 브라우저에 앱 쿠키가 남지 않는다. */
    private void assertSessionEnded(BrowserClient browser, Exchange response, String sid) {
        assertThat(AppSessions.countBySid(app, sid)).as("세션 행 삭제").isZero();
        for (String name : SESSION_COOKIES) {
            assertThat(response.setCookie(name)).as(name + " 삭제").hasValueSatisfying(c -> assertThat(c.raw()).contains("Max-Age=0"));
        }
        assertThat(browser.cookies()).noneMatch(c -> c.matchesHost(API_HOST));
    }
}
