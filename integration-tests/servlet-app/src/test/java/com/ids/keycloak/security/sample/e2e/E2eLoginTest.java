package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;
import com.ids.keycloak.security.sample.e2e.BrowserClient.StoredCookie;

import tools.jackson.databind.JsonNode;

/**
 * V3-07 로그인 (#118): 실제 Keycloak과 샘플 앱으로 LOGIN-01~08, COOKIE-01~03을 본다 (02 문서 3·4절).
 * 샘플 앱 설정은 액세스 토큰 60초, 절대 상한 3분이다 (03 문서 2절).
 */
@E2eTest
class E2eLoginTest {

    private static final String API_HOST = "api.kss.test";
    private static final String FRONTEND = BrowserClient.FRONTEND_ORIGIN;
    private static final String CALLBACK = "/login/oauth2/code/keycloak";
    private static final Pattern MAX_AGE = Pattern.compile("(?i)Max-Age=(\\d+)");

    private final E2eEnvironment env = E2eEnvironment.get();

    @AfterEach
    void resetClock() {
        SampleApps.demo().clock().reset();
    }

    @Test
    @DisplayName("LOGIN-01 쿠키 없이 /api/me를 부르면 401 JSON에 오류 코드와 로그인 주소가 온다")
    void login01Unauthenticated() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange me = browser.get(app.url("/api/me"));

            assertThat(me.status()).isEqualTo(401);
            assertThat(me.header("Content-Type")).hasValueSatisfying(type -> assertThat(type).startsWith("application/json"));
            JsonNode body = AppSessions.json(me.body());
            assertThat(body.get("code").asString()).isEqualTo("AUTHENTICATION_REQUIRED");
            assertThat(body.get("loginUrl").asString()).isEqualTo("/oauth2/authorization/keycloak");
            assertThat(me.headers("Set-Cookie")).as("401에 세션 쿠키를 만들지 않는다").isEmpty();
        }
    }

    @Test
    @DisplayName("LOGIN-02 로그인 시작은 Keycloak 인가 주소로 302, PKCE S256·state·nonce·scope=openid, login 쿠키 5분, HttpSession 없음")
    void login02AuthorizationRedirect() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange start = browser.get(app.url("/oauth2/authorization/keycloak?return=/items/3"));

            assertThat(start.status()).isEqualTo(302);
            assertThat(start.location().toString()).startsWith(env.issuer() + "/protocol/openid-connect/auth?");
            Map<String, String> query = query(start.location().getRawQuery());
            assertThat(query).containsEntry("code_challenge_method", "S256")
                .containsEntry("scope", "openid")
                .containsEntry("response_type", "code")
                .containsKeys("code_challenge", "state", "nonce");
            StoredCookie login = start.setCookie("__Host-demo_login").orElseThrow();
            assertThat(maxAge(login)).isEqualTo(300);
            assertThat(login.secure()).isTrue();
            assertThat(login.httpOnly()).isTrue();
            assertThat(login.value()).as("암호화돼 있어 돌아갈 경로가 그대로 보이지 않는다").doesNotContain("items");
            assertThat(start.headers("Set-Cookie")).noneMatch(c -> c.startsWith("JSESSIONID"));
        }
    }

    @Test
    @DisplayName("LOGIN-03 로그인 뒤 화면 주소 /items/3으로 302, 쿠키 3개, DB 세션 행 1개")
    void login03CallbackCreatesSession() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "/oauth2/authorization/keycloak?return=/items/3", "alice", "alice-test-password");

            assertThat(login.callback().status()).isEqualTo(302);
            assertThat(login.callback().header("Location")).hasValue(FRONTEND + "/items/3");
            assertThat(setCookieNames(login.callback())).contains("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf");
            String sid = sid(browser, "demo");
            assertThat(AppSessions.countBySid(app, sid)).isEqualTo(1);
            Map<String, Object> row = AppSessions.rowBySid(app, sid);
            JsonNode at = AppSessions.claims(browser.cookie(API_HOST, "__Host-demo_at").orElseThrow().value());
            assertThat(row.get("keycloak_user_id")).isEqualTo(at.get("sub").asString());
            assertThat(row.get("kc_sid")).isEqualTo(at.get("sid").asString());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://evil.example", "//evil.example", "/\\evil", "javascript:alert(1)"})
    @DisplayName("LOGIN-04 다른 사이트로 가는 return은 모두 화면 주소 /로 돌아간다")
    void login04OpenRedirectIsBlocked(String evil) throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app,
                "/oauth2/authorization/keycloak?return=" + URLEncoder.encode(evil, StandardCharsets.UTF_8), "alice", "alice-test-password");

            assertThat(login.callback().header("Location")).hasValue(FRONTEND + "/");
        }
    }

    @Test
    @DisplayName("LOGIN-05 콜백의 state를 바꾸면 로그인 실패, 세션 행이 생기지 않는다")
    void login05TamperedState() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            String callback = browser.authorize(app, "/oauth2/authorization/keycloak", "alice", "alice-test-password")
                .submitted().location().toString();
            String tampered = callback.replaceFirst("([?&]state=)[^&]+", "$1tampered-state");
            assertThat(tampered).isNotEqualTo(callback);

            assertLoginFails(app, browser, tampered);
        }
    }

    @Test
    @DisplayName("LOGIN-05 login 쿠키를 지우고 콜백하면 로그인 실패, 세션 행이 생기지 않는다")
    void login05MissingLoginCookie() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            String callback = browser.authorize(app, "/oauth2/authorization/keycloak", "alice", "alice-test-password")
                .submitted().location().toString();
            browser.removeCookie(API_HOST, "__Host-demo_login");

            assertLoginFails(app, browser, callback);
        }
    }

    @Test
    @DisplayName("LOGIN-05 login 쿠키가 5분 지났으면 (앱 시계 +6분) 로그인 실패, 세션 행이 생기지 않는다")
    void login05ExpiredLoginCookie() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            String callback = browser.authorize(app, "/oauth2/authorization/keycloak", "alice", "alice-test-password")
                .submitted().location().toString();
            app.clock().advance(Duration.ofMinutes(6));

            assertLoginFails(app, browser, callback);
        }
    }

    @Test
    @DisplayName("LOGIN-06 예전 sid 쿠키가 있는 채로 다시 로그인하면 예전 행은 지워지고 새 sid가 나온다")
    void login06SessionFixation() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String before = sid(browser, "demo");
            assertThat(AppSessions.countBySid(app, before)).isEqualTo(1);

            BrowserClient.Login again = browser.ssoLogin(app, "/oauth2/authorization/keycloak");

            assertThat(again.callback().status()).isEqualTo(302);
            String after = sid(browser, "demo");
            assertThat(after).isNotEqualTo(before);
            assertThat(AppSessions.countBySid(app, before)).as("예전 행").isZero();
            assertThat(AppSessions.countBySid(app, after)).as("새 행").isEqualTo(1);
        }
    }

    @Test
    @DisplayName("LOGIN-07 ID 토큰은 쿠키에도 DB에도 저장되지 않는다")
    void login07IdTokenIsNotStored() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "bob", "bob-test-password");

            Set<String> appCookies = browser.cookies().stream().filter(c -> c.matchesHost(API_HOST)).map(StoredCookie::name)
                .collect(Collectors.toSet());
            assertThat(appCookies).containsExactlyInAnyOrder("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf");
            for (StoredCookie cookie : browser.cookies()) {
                if (cookie.matchesHost(API_HOST) && cookie.value().startsWith("eyJ")) {
                    assertThat(AppSessions.claims(cookie.value()).get("typ").asString())
                        .as(cookie.name() + "에 든 JWT는 액세스 토큰(Bearer)이어야 한다").isEqualTo("Bearer");
                }
            }
            assertThat(login.callback().headers("Set-Cookie")).noneMatch(c -> c.contains("id_token"));
            String rowText = AppSessions.rowBySid(app, sid(browser, "demo")).values().stream()
                .map(v -> v instanceof byte[] b ? new String(b, StandardCharsets.ISO_8859_1) : String.valueOf(v))
                .collect(Collectors.joining("|"));
            assertThat(rowText).as("행에 JWT 원문이 없다").doesNotContain("eyJ");
        }
    }

    @Test
    @DisplayName("LOGIN-08 demo에 로그인한 뒤 demo2로 가면 Keycloak 화면 없이 demo2 세션이 따로 생기고, 두 앱 토큰의 sid가 같다")
    void login08SsoAcrossTwoApps() throws Exception {
        SampleApps.Running demo = SampleApps.demo();
        SampleApps.Running demo2 = SampleApps.demo2();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(demo, "alice", "alice-test-password");

            BrowserClient.Login sso = browser.ssoLogin(demo2, "/oauth2/authorization/keycloak");

            assertThat(sso.callback().header("Location")).hasValue(FRONTEND + "/");
            String demoSid = sid(browser, "demo");
            String demo2Sid = sid(browser, "demo2");
            assertThat(demo2Sid).isNotEqualTo(demoSid);
            assertThat(AppSessions.countBySid(demo2, demo2Sid)).as("demo2 DB(스키마 demo2)에 행").isEqualTo(1);
            assertThat(AppSessions.countBySid(demo, demo2Sid)).as("demo DB에는 demo2 행이 없다").isZero();
            assertThat(AppSessions.countBySid(demo, demoSid)).as("demo 세션은 그대로").isEqualTo(1);

            JsonNode demoAt = AppSessions.claims(browser.cookie(API_HOST, "__Host-demo_at").orElseThrow().value());
            JsonNode demo2At = AppSessions.claims(browser.cookie(API_HOST, "__Host-demo2_at").orElseThrow().value());
            assertThat(demo2At.get("sid").asString()).isEqualTo(demoAt.get("sid").asString());
            assertThat(demo2At.get("azp").asString()).isEqualTo("demo2");
            assertThat(demoAt.get("azp").asString()).isEqualTo("demo");
        }
    }

    @Test
    @DisplayName("COOKIE-01 sid·at·csrf 쿠키는 Secure, HttpOnly, SameSite=Lax, Path=/이고 Domain이 없다")
    void cookie01Attributes() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "alice", "alice-test-password");

            for (String name : List.of("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf")) {
                StoredCookie cookie = login.callback().setCookie(name).orElseThrow(() -> new AssertionError(name + " 없음"));
                assertThat(cookie.secure()).as(name + " Secure").isTrue();
                assertThat(cookie.httpOnly()).as(name + " HttpOnly").isTrue();
                assertThat(cookie.sameSite()).as(name + " SameSite").isEqualTo("Lax");
                assertThat(cookie.path()).as(name + " Path").isEqualTo("/");
                assertThat(cookie.hostOnly()).as(name + " Domain 없음").isTrue();
                assertThat(cookie.raw()).as(name).doesNotContainIgnoringCase("domain=");
            }
        }
    }

    @Test
    @DisplayName("COOKIE-02 로그인 응답에 id_token·access_token·JSESSIONID 쿠키가 없고, login 쿠키는 Max-Age=0으로 지워진다")
    void cookie02NoOtherCookies() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "alice", "alice-test-password");

            assertThat(setCookieNames(login.callback())).doesNotContain("id_token", "access_token", "JSESSIONID");
            assertThat(maxAge(login.callback().setCookie("__Host-demo_login").orElseThrow())).isZero();
            assertThat(browser.history()).filteredOn(e -> e.uri().getHost().equals(API_HOST))
                .allSatisfy(e -> assertThat(e.headers("Set-Cookie")).noneMatch(c -> c.startsWith("JSESSIONID")));
            assertThat(browser.cookie(API_HOST, "__Host-demo_login")).isEmpty();
        }
    }

    @Test
    @DisplayName("COOKIE-03 at 수명은 토큰 남은 시간 이하, sid·csrf는 절대 상한(3분) 남은 시간 이하")
    void cookie03Lifetimes() throws Exception {
        SampleApps.Running app = SampleApps.demo();
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "alice", "alice-test-password");
            Instant now = Instant.now();

            StoredCookie at = login.callback().setCookie("__Host-demo_at").orElseThrow();
            long tokenRemaining = AppSessions.claims(at.value()).get("exp").asLong() - now.getEpochSecond();
            assertThat(maxAge(at)).isPositive().isLessThanOrEqualTo(tokenRemaining + 1);
            for (String name : List.of("__Host-demo_sid", "__Host-demo_csrf")) {
                long maxAge = maxAge(login.callback().setCookie(name).orElseThrow());
                assertThat(maxAge).as(name).isPositive().isLessThanOrEqualTo(Duration.ofMinutes(3).toSeconds());
            }
            Map<String, Object> row = AppSessions.rowBySid(app, sid(browser, "demo"));
            long absoluteRemaining = AppSessions.instant(row.get("absolute_expires_at")).getEpochSecond() - now.getEpochSecond();
            assertThat(maxAge(login.callback().setCookie("__Host-demo_sid").orElseThrow())).isLessThanOrEqualTo(absoluteRemaining + 1);
        }
    }

    // ---- 도움 ----

    private void assertLoginFails(SampleApps.Running app, BrowserClient browser, String callbackUrl) {
        int before = AppSessions.count(app);

        Exchange callback = browser.get(callbackUrl);

        assertThat(callback.status()).isEqualTo(302);
        assertThat(callback.header("Location")).hasValue(FRONTEND + "/?login_error=invalid_state");
        assertThat(setCookieNames(callback)).doesNotContain("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf");
        assertThat(browser.cookie(API_HOST, "__Host-demo_login")).as("login 쿠키도 지운다").isEmpty();
        assertThat(AppSessions.count(app)).as("세션 행이 생기지 않는다").isEqualTo(before);
    }

    private static String sid(BrowserClient browser, String app) {
        return browser.cookie(API_HOST, "__Host-" + app + "_sid").orElseThrow(() -> new AssertionError(app + " sid 쿠키가 없다")).value();
    }

    private static Set<String> setCookieNames(Exchange exchange) {
        return exchange.headers("Set-Cookie").stream().map(c -> c.substring(0, c.indexOf('=')).trim()).collect(Collectors.toSet());
    }

    private static long maxAge(StoredCookie cookie) {
        Matcher m = MAX_AGE.matcher(cookie.raw());
        if (!m.find()) {
            throw new AssertionError("Max-Age가 없다: " + cookie.raw());
        }
        return Long.parseLong(m.group(1));
    }

    private static Map<String, String> query(String rawQuery) {
        return java.util.Arrays.stream(rawQuery.split("&"))
            .map(p -> p.split("=", 2))
            .collect(Collectors.toMap(p -> p[0], p -> p.length > 1 ? java.net.URLDecoder.decode(p[1], StandardCharsets.UTF_8) : "",
                (a, b) -> a));
    }
}
