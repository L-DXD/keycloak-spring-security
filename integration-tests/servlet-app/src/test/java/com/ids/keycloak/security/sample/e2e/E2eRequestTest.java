package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;

import tools.jackson.databind.JsonNode;

/**
 * V3-08 요청 인증 (#119): 로그인한 쿠키로 API를 부를 때 Keycloak도 DB도 부르지 않는지 실제 Keycloak·PostgreSQL로 본다
 * (REQ-01~05, JWT-09). REQ-06(사용자 변환기)은 스타터 통합 테스트가 본다.
 */
@E2eTest
class E2eRequestTest {

    private static final String API_HOST = "api.kss.test";
    /** Keycloak을 불렀다는 흔적이 되는 사용자 이벤트 (realm 설정에서 저장을 켰다). */
    private static final List<String> KEYCLOAK_CALLS = List.of("INTROSPECT_TOKEN", "USER_INFO_REQUEST", "REFRESH_TOKEN", "CODE_TO_TOKEN");

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);

    @Test
    @DisplayName("REQ-01 로그인한 쿠키로 GET /api/me → 200, 본문의 sub가 테스트 사용자(alice)다")
    void req01Me() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(200);
            JsonNode body = AppSessions.json(me.body());
            assertThat(body.get("sub").asString()).isEqualTo(admin.userId("alice"));
            assertThat(me.headers("Set-Cookie")).as("통과한 요청은 쿠키를 새로 쓰지 않는다").isEmpty();
        }
    }

    @Test
    @DisplayName("REQ-02 쿠키 없이 permit-all 경로(/api/public/ping) → 200")
    void req02PermitAll() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange ping = browser.get(app.url("/api/public/ping"));

            assertThat(ping.status()).isEqualTo(200);
            assertThat(ping.body()).contains("\"pong\":true");
        }
    }

    @Test
    @DisplayName("REQ-03 로그인한 쿠키로 요청 20번 → 세션 테이블에 보낸 SQL이 0개다")
    void req03NoSessionLookup() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            app.sql().clear();

            for (int i = 0; i < 20; i++) {
                assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
            }

            assertThat(app.sql().sessionTableStatements()).isEmpty();
        }
    }

    @Test
    @DisplayName("REQ-04 at 쿠키 서명을 망가뜨리면 401, 세션 행·쿠키 삭제, 감사 로그 사유 invalid_token, Keycloak 갱신 호출 없음")
    void req04TamperedSignature() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of("com.ids.keycloak.security.audit")) {
            browser.login(app, "alice", "alice-test-password");
            String sid = browser.cookie(API_HOST, "__Host-demo_sid").orElseThrow().value();
            Object rowId = AppSessions.rowBySid(app, sid).get("id");
            String kcSid = (String) AppSessions.rowBySid(app, sid).get("kc_sid");
            String at = browser.cookie(API_HOST, "__Host-demo_at").orElseThrow().value();
            browser.replaceCookieValue(API_HOST, "__Host-demo_at", tamperSignature(at));
            int refreshesBefore = admin.sessionEvents("REFRESH_TOKEN", kcSid).size();

            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertThat(AppSessions.json(me.body()).get("code").asString()).isEqualTo("AUTHENTICATION_REQUIRED");
            assertThat(AppSessions.countBySid(app, sid)).as("세션 행 삭제").isZero();
            for (String name : List.of("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf", "__Host-demo_login")) {
                assertThat(me.setCookie(name)).as(name + " 삭제").hasValueSatisfying(c -> assertThat(c.raw()).contains("Max-Age=0"));
            }
            assertThat(browser.cookies()).noneMatch(c -> c.matchesHost(API_HOST));
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=invalid_token") && m.contains("session=" + rowId));
            assertThat(admin.sessionEvents("REFRESH_TOKEN", kcSid)).as("Keycloak 갱신 호출 없음").hasSize(refreshesBefore);
        }
    }

    @Test
    @DisplayName("REQ-05 로그인과 요청 동안 응답에 JSESSIONID가 없고 서버에 HttpSession이 만들어지지 않는다")
    void req05NoHttpSession() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        int before = app.httpSessions().created();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            browser.get(app.url("/api/me"));
            browser.get(app.url("/api/public/ping"));
            browser.get(app.url("/api/nothing-here"));

            assertThat(app.httpSessions().created()).as(app.httpSessions().lastCreatedBy()).isEqualTo(before);
            assertThat(browser.history()).allSatisfy(e -> assertThat(e.headers("Set-Cookie")).noneMatch(c -> c.startsWith("JSESSIONID")));
        }
    }

    @Test
    @DisplayName("JWT-09 로그인한 상태에서 GET /api/me 100번 → Keycloak introspect·userinfo·token 호출 0번 (Keycloak 이벤트로 확인)")
    void jwt09NoKeycloakCallsPerRequest() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "bob", "bob-test-password");
            Instant start = Instant.now();

            for (int i = 0; i < 100; i++) {
                assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
            }

            assertThat(keycloakCallsSince(start)).containsOnly(Map.entry("INTROSPECT_TOKEN", 0), Map.entry("USER_INFO_REQUEST", 0),
                Map.entry("REFRESH_TOKEN", 0), Map.entry("CODE_TO_TOKEN", 0));
        }
    }

    private Map<String, Integer> keycloakCallsSince(Instant start) {
        return KEYCLOAK_CALLS.stream().collect(java.util.stream.Collectors.toMap(t -> t, t -> admin.eventsSince(t, "demo", start).size()));
    }

    /** JWT 서명 부분의 글자 하나를 바꾼다. 형식은 그대로라 만료가 아닌 서명 실패가 된다. */
    private static String tamperSignature(String jwt) {
        int dot = jwt.lastIndexOf('.');
        char[] signature = jwt.substring(dot + 1).toCharArray();
        int middle = signature.length / 2;
        signature[middle] = signature[middle] == 'A' ? 'B' : 'A';
        return jwt.substring(0, dot + 1) + new String(signature);
    }
}
