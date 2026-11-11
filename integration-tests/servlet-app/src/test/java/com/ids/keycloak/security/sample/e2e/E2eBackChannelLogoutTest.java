package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;

/**
 * V3-12 back-channel 로그아웃 (#123): Keycloak이 서버끼리 보내는 {@code logout_token}으로 다른 앱의 세션 행을 지운다 (BCL-01~04).
 * BCL-01은 실제 Keycloak이 보내는 토큰, BCL-02~04는 테스트 realm에 넣은 E2E 전용 키로 직접 서명한 토큰({@link E2eLogoutTokens})을 쓴다.
 */
@E2eTest
class E2eBackChannelLogoutTest {

    private static final String API_HOST = "api.kss.test";
    private static final String BACK_CHANNEL = "/logout/connect/back-channel/keycloak";
    private static final Header FROM_FRONTEND = new BasicHeader("Origin", BrowserClient.FRONTEND_ORIGIN);
    private static final String AUDIT_LOGGER = "com.ids.keycloak.security.audit";

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);
    private final E2eLogoutTokens tokens = E2eLogoutTokens.get();
    private final SampleApps.Running app = SampleApps.demo();

    @Test
    @DisplayName("BCL-01 demo와 demo2에 같은 사람이 로그인(SSO) → demo에서 POST /logout → Keycloak이 demo2에 logout_token을 보내 demo2 행이 지워진다. demo2는 at가 끝나면 401")
    void bcl01() throws Exception {
        SampleApps.Running demo2 = SampleApps.demo2();
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            browser.ssoLogin(demo2, "/oauth2/authorization/keycloak");
            String sid = sid(browser, app);
            String sid2 = sid(browser, demo2);
            Map<String, Object> row2 = AppSessions.rowBySid(demo2, sid2);
            assertThat(row2.get("kc_sid")).as("SSO라 Keycloak 세션이 같다").isEqualTo(AppSessions.rowBySid(app, sid).get("kc_sid"));

            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), FROM_FRONTEND, xsrf(csrfToken(browser, app)));

            assertThat(logout.status()).isEqualTo(302);
            assertThat(logout.header("Location")).hasValue(BrowserClient.FRONTEND_ORIGIN + "/logged-out");
            assertThat(AppSessions.countBySid(demo2, sid2)).as("Keycloak이 demo2에 back-channel 로그아웃을 보냈다").isZero();
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=backchannel_logout") && m.contains("session=" + row2.get("id")));

            assertThat(browser.get(demo2.url("/api/me")).status()).as("at는 만료 전까지 스스로 통한다 (요청마다 DB를 보지 않는다)").isEqualTo(200);
            browser.removeCookie(API_HOST, "__Host-demo2_at");
            Exchange me = browser.get(demo2.url("/api/me"));
            assertThat(me.status()).as("at가 끝나 갱신하려 하면 행이 없다").isEqualTo(401);
            assertThat(browser.cookie(API_HOST, "__Host-demo2_sid")).isEmpty();
        }
    }

    @Test
    @DisplayName("BCL-02 realm에 없는 키로 서명 / aud가 다른 앱 / events 없음 / nonce 있음 / sid 없음 / logout_token 없음 → 400, 행은 그대로")
    void bcl02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             BrowserClient keycloak = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            String kcSid = (String) AppSessions.rowBySid(app, sid).get("kc_sid");
            String sub = admin.userId("alice");

            Map<String, String> invalid = new java.util.LinkedHashMap<>();
            invalid.put("realm에 없는 키", tokens.signWithForeignKey(tokens.claims("demo", sub, kcSid)));
            invalid.put("aud가 demo2", tokens.sign(tokens.claims("demo2", sub, kcSid)));
            invalid.put("events 없음", tokens.sign(edit(tokens.claims("demo", sub, kcSid), c -> c.remove("events"))));
            invalid.put("nonce 있음", tokens.sign(edit(tokens.claims("demo", sub, kcSid), c -> c.put("nonce", "n-1"))));
            invalid.put("iss가 다름", tokens.sign(edit(tokens.claims("demo", sub, kcSid), c -> c.put("iss", env.issuer() + "-other"))));
            invalid.put("sid 없음(sub만)", tokens.sign(tokens.claims("demo", sub, null)));

            for (Map.Entry<String, String> token : invalid.entrySet()) {
                Exchange response = keycloak.postForm(app.url(BACK_CHANNEL), Map.of("logout_token", token.getValue()));
                assertThat(response.status()).as(token.getKey()).isEqualTo(400);
                assertThat(response.body()).as(token.getKey()).contains("invalid_request");
            }
            Exchange missing = keycloak.postForm(app.url(BACK_CHANNEL), Map.of());
            assertThat(missing.status()).as("logout_token 없음").isEqualTo(400);

            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);
            assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("BCL-03 행이 이미 없는 sid의 맞는 logout_token → 200")
    void bcl03() throws Exception {
        try (BrowserClient keycloak = new BrowserClient(env.caCertificate())) {
            String token = tokens.sign(tokens.claims("demo", UUID.randomUUID().toString(), "no-such-" + UUID.randomUUID()));

            Exchange response = keycloak.postForm(app.url(BACK_CHANNEL), Map.of("logout_token", token));

            assertThat(response.status()).isEqualTo(200);
            assertThat(response.header("Cache-Control")).hasValue("no-store");
        }
    }

    @Test
    @DisplayName("BCL-04 back-channel 주소는 CSRF 토큰·Origin 없이 받는다(서명으로 보호): 맞는 logout_token → 200, 그 sid의 행 삭제(사유 backchannel_logout), 쿠키 안 씀")
    void bcl04() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             BrowserClient keycloak = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            String token = tokens.sign(tokens.claims("demo", admin.userId("alice"), (String) row.get("kc_sid")));

            Exchange response = keycloak.postForm(app.url(BACK_CHANNEL), Map.of("logout_token", token));

            assertThat(response.status()).isEqualTo(200);
            assertThat(response.headers("Set-Cookie")).isEmpty();
            assertThat(AppSessions.countBySid(app, sid)).isZero();
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=backchannel_logout") && m.contains("session=" + row.get("id")));
        }
    }

    private static Map<String, Object> edit(Map<String, Object> claims, Consumer<Map<String, Object>> change) {
        change.accept(claims);
        return claims;
    }

    private static String sid(BrowserClient browser, SampleApps.Running app) {
        return browser.cookie(API_HOST, "__Host-" + app.clientId() + "_sid").orElseThrow().value();
    }

    private static String csrfToken(BrowserClient browser, SampleApps.Running app) {
        Exchange response = browser.get(app.url("/api/csrf"));
        assertThat(response.status()).isEqualTo(200);
        return AppSessions.json(response.body()).get("token").asString();
    }

    private static Header xsrf(String token) {
        return new BasicHeader("X-XSRF-TOKEN", token);
    }
}
