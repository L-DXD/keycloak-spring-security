package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * E2E-04: 테스트 도구가 브라우저 없이 Keycloak 로그인 화면을 HTTP로 채워 로그인한다.
 * <p>
 * 앱 쿠키 이름·속성(__Host-…)은 #84(LOGIN-01~)에서 본다. 여기서는 로그인 흐름이 실제 Keycloak과 끝까지 도는지만 본다.
 */
@E2eTest
class E2e04LoginTest {

    private final E2eEnvironment env = E2eEnvironment.get();

    @Test
    @DisplayName("E2E-04 alice가 Keycloak 로그인 폼을 HTTP로 채워 로그인하고, 쿠키 상자에 앱 쿠키가 남는다")
    void logsInThroughKeycloakLoginForm() throws Exception {
        SampleApps.Running app = SampleApps.demo();

        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Login login = browser.login(app, "alice", "alice-test-password");

            assertThat(login.start().location().toString())
                .as("Keycloak 인가 주소로 보낸다")
                .startsWith(env.issuer() + "/protocol/openid-connect/auth?");
            assertThat(login.start().location().getQuery())
                .as("PKCE S256")
                .contains("code_challenge_method=S256");
            assertThat(login.submitted().location().toString())
                .as("Keycloak이 앱 콜백으로 돌려보낸다")
                .startsWith(app.url("/login/oauth2/code/keycloak?"));
            assertThat(login.callback().status()).as("콜백 처리 뒤 302").isEqualTo(302);
            assertThat(browser.cookies())
                .as("앱(api.kss.test)이 준 쿠키가 있다")
                .anyMatch(c -> c.matchesHost("api.kss.test"));

            BrowserClient.Exchange me = browser.get(app.url("/api/me"));
            assertThat(me.status()).isEqualTo(200);
            assertThat(me.body()).contains("\"name\":\"alice\"");
        }
    }

    @Test
    @DisplayName("E2E-04 비밀번호가 틀리면 Keycloak 로그인 화면에 머문다")
    void wrongPasswordStaysOnLoginPage() throws Exception {
        SampleApps.Running app = SampleApps.demo();

        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Exchange page = browser.follow(browser.get(app.url("/oauth2/authorization/keycloak")));
            String action = BrowserClient.loginFormAction(page);

            BrowserClient.Exchange submitted = browser.postForm(action, Map.of("username", "alice", "password", "wrong", "credentialId", ""));

            assertThat(submitted.status()).isEqualTo(200);
            assertThat(submitted.body()).contains("kc-form-login");
        }
    }
}
