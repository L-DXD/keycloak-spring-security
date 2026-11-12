package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.sample.e2e.BrowserClient.Exchange;

/**
 * V3-13 로그 점검 (#124, EVT-02): 테스트 JVM이 남긴 모든 로그(샘플 앱 두 개, 라이브러리는 DEBUG까지)에 토큰 모양(JWT)과 샘플 앱이 준
 * {@code __Host-} 쿠키 값(sid·at·csrf·login)이 하나도 없는지 본다. 리프레시 토큰도 Keycloak에서는 JWT라 같이 걸린다.
 * <p>
 * 클래스 이름순으로 돌아 맨 끝에 돈다({@code junit-platform.properties}). 혼자 돌려도 의미가 있게 로그인·갱신·잘못된 토큰·로그아웃을
 * 먼저 한 번 한다.
 */
@E2eTest
class E2eZzLogHygieneTest {

    /** 헤더.페이로드.서명. 가린 값({@code eyJ***.[redacted]})은 걸리지 않는다. */
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}");
    private static final String API_HOST = "api.kss.test";
    private static final String FORGED_AT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvcmdlZCJ9.eyJzdWIiOiJtYWxsb3J5IiwiZXhwIjo0MTAyNDQ0ODAwfQ."
        + "Zm9yZ2VkLXNpZ25hdHVyZS12YWx1ZQ";

    private final E2eEnvironment env = E2eEnvironment.get();
    private final SampleApps.Running app = SampleApps.demo();

    @Test
    @DisplayName("EVT-02 모든 E2E 시나리오의 로그에 토큰 모양(eyJ로 시작하는 JWT), 리프레시 토큰, sid 등 쿠키 원문이 없다")
    void evt02() throws Exception {
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            browser.removeCookie(API_HOST, "__Host-demo_at");
            assertThat(browser.get(app.url("/api/me")).status()).isEqualTo(200);
            browser.replaceCookieValue(API_HOST, "__Host-demo_at", FORGED_AT);
            // 모르는 kid: JWKS를 받은 지 token.jwks-min-refetch-interval(기본 5분)이 안 됐으면 503, 지났으면 다시 받아 보고 401 (JWT-08). 어느 쪽이든 그 값이 로그에 남으면 안 된다
            assertThat(browser.get(app.url("/api/me")).status()).as("위조 토큰").isIn(401, 503);
        }
        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            browser.login(app, "alice", "alice-test-password");
            Exchange csrf = browser.get(app.url("/api/csrf"));
            String token = AppSessions.json(csrf.body()).get("token").asString();
            assertThat(browser.postForm(app.url("/logout"), Map.of(), new BasicHeader("Origin", BrowserClient.FRONTEND_ORIGIN),
                new BasicHeader("X-XSRF-TOKEN", token)).status()).isEqualTo(302);
        }

        List<String> lines = E2eLogRecorder.lines();
        Set<String> cookieValues = BrowserClient.issuedCookieValues();
        assertThat(lines).as("로그를 모았다").anyMatch(l -> l.contains("[KSS] 세션 끝남 reason=logout"));
        assertThat(lines).as("라이브러리 DEBUG 로그도 모았다").anyMatch(l -> l.startsWith("DEBUG com.ids.keycloak.security"));
        assertThat(lines).as("MDC도 같이 본다").anyMatch(l -> l.contains("traceId="));
        assertThat(cookieValues).as("샘플 앱이 준 쿠키 값을 모았다").isNotEmpty();

        assertThat(lines).as("JWT 모양").noneMatch(l -> JWT.matcher(l).find());
        for (String value : cookieValues) {
            assertThat(lines).as("쿠키 값 %s…", value.substring(0, 4)).noneMatch(l -> l.contains(value));
        }
    }
}
