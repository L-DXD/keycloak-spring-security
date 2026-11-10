package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.UriComponentsBuilder;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenException;
import com.ids.keycloak.security.web.refresh.KeycloakTokenResponse;

import tools.jackson.databind.JsonNode;

/**
 * V3-11 로그아웃 (#87): 실제 Keycloak으로 로그인한 쿠키로 샘플 앱의 {@code POST /logout}을 부른다 (LOGOUT-01~06).
 * 화면은 {@code https://app.kss.test}이고, 로그아웃 뒤 화면 주소는 {@code https://app.kss.test/logged-out}이다.
 */
@E2eTest
class E2eLogoutTest {

    private static final String API_HOST = "api.kss.test";
    private static final String FRONTEND_LOGOUT = BrowserClient.FRONTEND_ORIGIN + "/logged-out";
    private static final Header FROM_FRONTEND = new BasicHeader("Origin", BrowserClient.FRONTEND_ORIGIN);
    private static final String AUDIT_LOGGER = "com.ids.keycloak.security.audit";
    private static final Pattern HIDDEN_SESSION_CODE = Pattern.compile("name=\"session_code\"\\s+value=\"([^\"]+)\"");

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);
    private final SampleApps.Running app = SampleApps.demo();

    @AfterEach
    void resetApps() {
        app.clock().reset();
        app.keycloakOutage().end();
        SampleApps.demo2().clock().reset();
    }

    @Test
    @DisplayName("LOGOUT-01 POST /logout(CSRF) → 화면 로그아웃 주소로 302, 행·쿠키 4개 삭제, Keycloak 세션도 끝(LOGOUT 이벤트). JSESSIONID 없음")
    void logout01() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate());
             LogCapture audit = LogCapture.of(AUDIT_LOGGER)) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            String kcSid = (String) row.get("kc_sid");
            String userId = admin.userId("alice");
            assertThat(admin.userSessions(userId)).contains(kcSid);

            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), FROM_FRONTEND, xsrf(csrfToken(browser)));

            assertThat(logout.status()).isEqualTo(302);
            assertThat(logout.header("Location")).hasValue(FRONTEND_LOGOUT);
            assertThat(logout.header("Cache-Control")).hasValue("no-store");
            assertSessionEnded(browser, logout, app, sid);
            assertThat(admin.sessionEvents("LOGOUT", kcSid)).as("Keycloak 로그아웃을 서버끼리 불렀다").hasSize(1);
            assertThat(admin.userSessions(userId)).as("Keycloak 세션도 끝났다").doesNotContain(kcSid);
            assertThat(audit.messages()).anyMatch(m -> m.contains("reason=logout") && m.contains("session=" + row.get("id")));
            assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(401);
        }
    }

    @Test
    @DisplayName("LOGOUT-02 앱이 Keycloak 로그아웃을 부르지 못했다 → 행·쿠키 삭제, Keycloak 로그아웃 주소로 302(client_id·post_logout_redirect_uri·state, id_token_hint 없음). 브라우저가 그 주소에서 확인하면 Keycloak 세션이 끝나고 화면으로 돌아온다")
    void logout02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            String kcSid = (String) AppSessions.rowBySid(app, sid).get("kc_sid");
            String token = csrfToken(browser);
            app.keycloakOutage().begin();

            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), FROM_FRONTEND, xsrf(token));

            app.keycloakOutage().end();
            assertThat(admin.userSessions(admin.userId("alice"))).as("앱은 Keycloak 세션을 끝내지 못했다").contains(kcSid);

            assertThat(logout.status()).isEqualTo(302);
            assertSessionEnded(browser, logout, app, sid);
            URI location = logout.location();
            Map<String, List<String>> query = UriComponentsBuilder.fromUri(location).build(true).getQueryParams();
            assertThat(location.toString()).startsWith(env.issuer() + "/protocol/openid-connect/logout?");
            assertThat(query.get("client_id")).containsExactly("demo");
            assertThat(location.getQuery()).contains("post_logout_redirect_uri=" + FRONTEND_LOGOUT);
            assertThat(query.get("state")).singleElement().satisfies(s -> assertThat(s).hasSizeGreaterThanOrEqualTo(20));
            assertThat(query).doesNotContainKey("id_token_hint");

            Exchange confirmPage = browser.follow(logout);
            assertThat(confirmPage.status()).as("id_token_hint가 없으니 Keycloak이 로그아웃할지 묻는다").isEqualTo(200);
            Exchange confirmed = confirm(browser, confirmPage);
            assertThat(confirmed.status()).isEqualTo(302);
            assertThat(confirmed.header("Location")).hasValueSatisfying(l -> assertThat(l)
                .startsWith(FRONTEND_LOGOUT + "?").contains("state=" + query.get("state").get(0)));
            assertThat(admin.userSessions(admin.userId("alice"))).as("Keycloak 세션도 끝났다").doesNotContain(kcSid);
        }
    }

    @Test
    @DisplayName("LOGOUT-03 GET /logout → 405, Allow: POST. 세션은 그대로")
    void logout03() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);

            Exchange get = browser.get(app.url("/logout"), FROM_FRONTEND);

            assertThat(get.status()).isEqualTo(405);
            assertThat(get.header("Allow")).hasValue("POST");
            assertThat(code(get)).isEqualTo("METHOD_NOT_ALLOWED");
            assertThat(get.headers("Set-Cookie")).isEmpty();
            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);
            assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("LOGOUT-04 CSRF 토큰 없이 POST /logout → 403 INVALID_CSRF_TOKEN. 행·쿠키·Keycloak 세션은 그대로")
    void logout04() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            String kcSid = (String) AppSessions.rowBySid(app, sid).get("kc_sid");

            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), FROM_FRONTEND);

            assertThat(logout.status()).isEqualTo(403);
            assertThat(code(logout)).isEqualTo("INVALID_CSRF_TOKEN");
            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);
            assertThat(browser.cookie(API_HOST, "__Host-demo_sid")).isPresent();
            assertThat(admin.userSessions(admin.userId("alice"))).contains(kcSid);
            assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("LOGOUT-05 로그인하지 않은 브라우저: /api/csrf 토큰으로 POST /logout → 화면 로그아웃 주소로 302 (Keycloak은 부르지 않는다)")
    void logout05() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            String token = csrfToken(browser);

            Exchange logout = browser.postForm(app.url("/logout"), Map.of(), FROM_FRONTEND, xsrf(token));

            assertThat(logout.status()).isEqualTo(302);
            assertThat(logout.header("Location")).hasValue(FRONTEND_LOGOUT);
            assertThat(browser.cookies()).filteredOn(c -> c.domain().equals(API_HOST)).isEmpty();
        }
    }

    @Test
    @DisplayName("LOGOUT-06 절대 상한으로 끝난 세션: 기본(demo)은 리프레시 토큰을 폐기하지 않고, 옵션을 켠 demo2는 폐기한다 (Keycloak이 그 토큰을 거절)")
    void logout06() throws Exception {
        SampleApps.Running demo2 = SampleApps.demo2();
        try (BrowserClient one = new BrowserClient(env.caCertificate());
             BrowserClient two = new BrowserClient(env.caCertificate())) {
            one.login(app, "alice", "alice-test-password");
            two.login(demo2, "alice", "alice-test-password");
            String refreshToken = AppSessions.refreshToken(app, sid(one, app));
            String refreshToken2 = AppSessions.refreshToken(demo2, sid(two, demo2));
            app.clock().advance(Duration.ofMinutes(3).plusSeconds(1));
            demo2.clock().advance(Duration.ofMinutes(3).plusSeconds(1));

            assertThat(one.get(app.url("/api/me")).status()).isEqualTo(401);
            assertThat(two.get(demo2.url("/api/me")).status()).isEqualTo(401);

            KeycloakTokenClient keycloak = app.context().getBean(KeycloakTokenClient.class);
            KeycloakTokenResponse stillAlive = keycloak.refresh(refreshToken);
            assertThat(stillAlive.accessToken()).as("기본: Keycloak 세션은 남는다 (D13)").isNotBlank();
            keycloak.logout(stillAlive.refreshToken());
            assertThatThrownBy(() -> demo2.context().getBean(KeycloakTokenClient.class).refresh(refreshToken2))
                .as("demo2: 앱이 폐기했다")
                .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isTrue());
        }
    }

    @Test
    @DisplayName("CSRF-07 HTML 폼의 숨은 칸 _csrf로 POST /logout → 302. 틀린 값이면 403")
    void csrf07Logout() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String sid = sid(browser, app);
            Map<String, String> form = new LinkedHashMap<>();
            form.put("_csrf", "k1.wrong.token");
            assertThat(browser.postForm(app.url("/logout"), form, FROM_FRONTEND).status()).isEqualTo(403);
            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);

            form.put("_csrf", csrfToken(browser));
            Exchange logout = browser.postForm(app.url("/logout"), form, FROM_FRONTEND);

            assertThat(logout.status()).isEqualTo(302);
            assertThat(logout.header("Location")).hasValue(FRONTEND_LOGOUT);
            assertThat(AppSessions.countBySid(app, sid)).isZero();
        }
    }

    /** 행이 없고, 응답이 세션 쿠키 4개를 지웠고(Max-Age=0), 브라우저에도 남지 않았다. HttpSession은 만들지 않았다. */
    private static void assertSessionEnded(BrowserClient browser, Exchange response, SampleApps.Running app, String sid) {
        assertThat(AppSessions.countBySid(app, sid)).isZero();
        for (String name : List.of("sid", "at", "csrf", "login")) {
            String cookie = "__Host-" + app.clientId() + "_" + name;
            assertThat(response.headers("Set-Cookie")).filteredOn(c -> c.startsWith(cookie + "=")).as(cookie + " 삭제는 한 번")
                .singleElement().satisfies(c -> assertThat(c).contains("Max-Age=0"));
            assertThat(browser.cookie(API_HOST, cookie)).isEmpty();
        }
        assertThat(response.headers("Set-Cookie")).noneMatch(c -> c.startsWith("JSESSIONID"));
    }

    /** Keycloak 로그아웃 확인 화면에서 "로그아웃"을 누른다. */
    private static Exchange confirm(BrowserClient browser, Exchange page) {
        Matcher code = HIDDEN_SESSION_CODE.matcher(page.body());
        assertThat(code.find()).as("확인 화면에 session_code가 있다: " + BrowserClient.abbreviate(page.body())).isTrue();
        Matcher action = Pattern.compile("<form[^>]*action=\"([^\"]+)\"").matcher(page.body());
        assertThat(action.find()).isTrue();
        Map<String, String> form = new LinkedHashMap<>();
        form.put("session_code", code.group(1));
        form.put("confirmLogout", "Logout");
        return browser.postForm(page.uri().resolve(action.group(1).replace("&amp;", "&")).toString(), form);
    }

    private static String sid(BrowserClient browser, SampleApps.Running app) {
        return browser.cookie(API_HOST, "__Host-" + app.clientId() + "_sid").orElseThrow().value();
    }

    private String csrfToken(BrowserClient browser) {
        Exchange response = browser.get(app.url("/api/csrf"));
        assertThat(response.status()).isEqualTo(200);
        return AppSessions.json(response.body()).get("token").asString();
    }

    private static Header xsrf(String token) {
        return new BasicHeader("X-XSRF-TOKEN", token);
    }

    private static String code(Exchange response) {
        JsonNode body = AppSessions.json(response.body());
        return body.get("code").asString();
    }
}
