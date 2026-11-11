package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;

import tools.jackson.databind.JsonNode;

/**
 * V3-10 CSRF·Origin·CORS (#121): 실제 Keycloak으로 로그인한 쿠키로 샘플 앱의 {@code POST /api/items}를 부른다 (CSRF-01~07, CORS-01·02).
 * 화면은 {@code https://app.kss.test}이고, 다른 화면 흉내는 같은 사이트의 {@code https://evil.kss.test}다(SameSite만으로는 못 막는 경우).
 */
@E2eTest
class E2eCsrfTest {

    private static final String API_HOST = "api.kss.test";
    private static final String CSRF_COOKIE = "__Host-demo_csrf";
    private static final String EVIL_ORIGIN = "https://evil.kss.test";
    private static final Header FROM_FRONTEND = new BasicHeader("Origin", BrowserClient.FRONTEND_ORIGIN);
    private static final String ITEM = "{\"name\":\"item-1\"}";

    private final E2eEnvironment env = E2eEnvironment.get();
    private final KeycloakAdmin admin = new KeycloakAdmin(env);
    private final SampleApps.Running app = SampleApps.demo();

    @Test
    @DisplayName("CSRF-01 로그인 뒤 GET /api/csrf → 200, 헤더 이름 X-XSRF-TOKEN, 칸 이름 _csrf, 토큰. 캐시하지 않고 쿠키를 새로 쓰지 않는다")
    void csrf01() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");

            Exchange response = browser.get(app.url("/api/csrf"));

            assertThat(response.status()).isEqualTo(200);
            JsonNode body = AppSessions.json(response.body());
            assertThat(body.get("headerName").asString()).isEqualTo("X-XSRF-TOKEN");
            assertThat(body.get("parameterName").asString()).isEqualTo("_csrf");
            assertThat(body.get("token").asString()).isNotBlank();
            assertThat(response.header("Cache-Control")).hasValue("no-store");
            assertThat(response.headers("Set-Cookie")).as("로그인 때 쓴 csrf 쿠키를 그대로 쓴다").isEmpty();
            assertThat(body.get("token").asString()).as("쿠키 원본이 아니라 가린 값을 준다")
                .isNotEqualTo(browser.cookie(API_HOST, CSRF_COOKIE).orElseThrow().value());
        }
    }

    @Test
    @DisplayName("CSRF-02 로그인 뒤 토큰 없이 POST /api/items → 403 INVALID_CSRF_TOKEN")
    void csrf02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");

            Exchange response = browser.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND);

            assertThat(response.status()).isEqualTo(403);
            assertThat(code(response)).isEqualTo("INVALID_CSRF_TOKEN");
        }
    }

    @Test
    @DisplayName("CSRF-03 CSRF-01 토큰을 X-XSRF-TOKEN 헤더에 넣어 POST /api/items → 201. /api/csrf를 다시 불러 받은 다른 모양의 토큰도 통한다")
    void csrf03() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String first = csrfToken(browser);
            String second = csrfToken(browser);

            Exchange created = browser.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(first));
            Exchange again = browser.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(second));

            assertThat(created.status()).isEqualTo(201);
            JsonNode body = AppSessions.json(created.body());
            assertThat(body.get("name").asString()).isEqualTo("item-1");
            assertThat(body.get("createdBy").asString()).isEqualTo(admin.userId("alice"));
            assertThat(first).as("BREACH: 응답마다 가린 값이 다르다").isNotEqualTo(second);
            assertThat(again.status()).isEqualTo(201);
        }
    }

    @Test
    @DisplayName("CSRF-04 사용자 A의 토큰을 사용자 B 쿠키로 POST → 403. A의 csrf 쿠키까지 B 브라우저에 심어도 sid 서명이 달라 403")
    void csrf04() throws Exception {
        try (BrowserClient alice = new BrowserClient(env.caCertificate());
             BrowserClient bob = new BrowserClient(env.caCertificate())) {
            alice.login(app, "alice", "alice-test-password");
            bob.login(app, "bob", "bob-test-password");
            String aliceToken = csrfToken(alice);
            String aliceCsrfCookie = alice.cookie(API_HOST, CSRF_COOKIE).orElseThrow().value();
            String bobToken = csrfToken(bob);
            String bobCsrfCookie = bob.cookie(API_HOST, CSRF_COOKIE).orElseThrow().value();

            Exchange withAliceToken = bob.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(aliceToken));
            assertThat(withAliceToken.status()).isEqualTo(403);
            assertThat(code(withAliceToken)).isEqualTo("INVALID_CSRF_TOKEN");

            bob.replaceCookieValue(API_HOST, CSRF_COOKIE, aliceCsrfCookie);
            Exchange planted = bob.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(aliceToken));
            assertThat(planted.status()).as("쿠키와 헤더가 같아도 bob의 sid로 서명된 토큰이 아니다").isEqualTo(403);
            assertThat(code(planted)).isEqualTo("INVALID_CSRF_TOKEN");

            bob.replaceCookieValue(API_HOST, CSRF_COOKIE, bobCsrfCookie);
            assertThat(bob.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(bobToken)).status()).as("bob 자신의 토큰").isEqualTo(201);
        }
    }

    @Test
    @DisplayName("CSRF-05 토큰이 맞아도 Origin이 다른 화면이면 403, Origin·Referer가 둘 다 없으면 403. Origin 없이 Referer가 화면 주소면 201")
    void csrf05() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            String token = csrfToken(browser);

            Exchange evil = browser.postJson(app.url("/api/items"), ITEM, new BasicHeader("Origin", EVIL_ORIGIN), xsrf(token));
            Exchange none = browser.postJson(app.url("/api/items"), ITEM, xsrf(token));
            Exchange evilReferer = browser.postJson(app.url("/api/items"), ITEM, new BasicHeader("Referer", EVIL_ORIGIN + "/page"), xsrf(token));
            Exchange frontendReferer = browser.postJson(app.url("/api/items"), ITEM,
                new BasicHeader("Referer", BrowserClient.FRONTEND_ORIGIN + "/items/3"), xsrf(token));

            assertThat(evil.status()).isEqualTo(403);
            assertThat(evil.header("Access-Control-Allow-Origin")).as("다른 화면은 응답을 읽지 못한다").isEmpty();
            assertThat(none.status()).isEqualTo(403);
            assertThat(code(none)).isEqualTo("ORIGIN_NOT_ALLOWED");
            assertThat(evilReferer.status()).isEqualTo(403);
            assertThat(code(evilReferer)).isEqualTo("ORIGIN_NOT_ALLOWED");
            assertThat(frontendReferer.status()).isEqualTo(201);
        }
    }

    @Test
    @DisplayName("CSRF-06 로그인 전 /api/csrf로 받은 토큰은 로그인 뒤 POST에서 403 (로그인하면 csrf 쿠키가 새 sid에 묶여 바뀐다)")
    void csrf06() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange anonymous = browser.get(app.url("/api/csrf"));
            assertThat(anonymous.status()).isEqualTo(200);
            assertThat(anonymous.setCookie(CSRF_COOKIE)).as("로그인 전에도 csrf 쿠키를 만든다").isPresent();
            String tokenBeforeLogin = AppSessions.json(anonymous.body()).get("token").asString();
            String cookieBeforeLogin = browser.cookie(API_HOST, CSRF_COOKIE).orElseThrow().value();

            BrowserClient.Login login = browser.login(app, "alice", "alice-test-password");

            assertThat(login.callback().setCookie(CSRF_COOKIE)).hasValueSatisfying(c -> assertThat(c.value()).isNotEqualTo(cookieBeforeLogin));
            assertThat(login.callback().headers("Set-Cookie")).filteredOn(c -> c.startsWith(CSRF_COOKIE + "="))
                .as("로그인 응답은 csrf 쿠키를 한 번만 쓴다").hasSize(1);
            Exchange stale = browser.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(tokenBeforeLogin));
            assertThat(stale.status()).isEqualTo(403);
            assertThat(code(stale)).isEqualTo("INVALID_CSRF_TOKEN");
            assertThat(browser.postJson(app.url("/api/items"), ITEM, FROM_FRONTEND, xsrf(csrfToken(browser))).status()).isEqualTo(201);
        }
    }

    @Test
    @DisplayName("CSRF-07 HTML 폼의 숨은 칸 _csrf로 POST /api/items(form) → 201 (POST /logout은 E2eLogoutTest가 같은 방법으로 본다)")
    void csrf07() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            Map<String, String> form = new LinkedHashMap<>();
            form.put("name", "form-item");
            form.put("_csrf", csrfToken(browser));

            Exchange created = browser.postForm(app.url("/api/items"), form, FROM_FRONTEND);

            assertThat(created.status()).isEqualTo(201);
            assertThat(AppSessions.json(created.body()).get("name").asString()).isEqualTo("form-item");

            form.put("_csrf", "k1.wrong.token");
            assertThat(browser.postForm(app.url("/api/items"), form, FROM_FRONTEND).status()).isEqualTo(403);
        }
    }

    @Test
    @DisplayName("CORS-01 쿠키 없이 화면 Origin으로 OPTIONS /api/items(사전 확인) → 200, Allow-Origin이 화면 주소, Allow-Credentials true, 허용 헤더에 X-XSRF-TOKEN")
    void cors01() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange preflight = browser.options(app.url("/api/items"), FROM_FRONTEND,
                new BasicHeader("Access-Control-Request-Method", "POST"),
                new BasicHeader("Access-Control-Request-Headers", "content-type,x-xsrf-token"));

            assertThat(preflight.status()).isEqualTo(200);
            assertThat(preflight.header("Access-Control-Allow-Origin")).hasValue(BrowserClient.FRONTEND_ORIGIN);
            assertThat(preflight.header("Access-Control-Allow-Credentials")).hasValue("true");
            assertThat(preflight.header("Access-Control-Allow-Headers")).hasValueSatisfying(h -> assertThat(h).containsIgnoringCase("x-xsrf-token"));
            assertThat(preflight.header("Access-Control-Allow-Methods")).hasValueSatisfying(h -> assertThat(h).contains("POST"));
            assertThat(preflight.headers("Set-Cookie")).isEmpty();

            Exchange simple = browser.get(app.url("/api/public/ping"), FROM_FRONTEND);
            assertThat(simple.header("Access-Control-Allow-Origin")).hasValue(BrowserClient.FRONTEND_ORIGIN);
        }
    }

    @Test
    @DisplayName("CORS-02 다른 Origin의 사전 확인 → 허용 헤더가 없다. *나 받은 Origin을 그대로 돌려주지 않는다")
    void cors02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            Exchange preflight = browser.options(app.url("/api/items"), new BasicHeader("Origin", EVIL_ORIGIN),
                new BasicHeader("Access-Control-Request-Method", "POST"),
                new BasicHeader("Access-Control-Request-Headers", "content-type,x-xsrf-token"));
            Exchange simple = browser.get(app.url("/api/public/ping"), new BasicHeader("Origin", EVIL_ORIGIN));

            for (Exchange response : new Exchange[] {preflight, simple}) {
                assertThat(response.header("Access-Control-Allow-Origin")).isEmpty();
                assertThat(response.header("Access-Control-Allow-Credentials")).isEmpty();
                assertThat(response.status()).isEqualTo(403);
            }
        }
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
        return AppSessions.json(response.body()).get("code").asString();
    }
}
