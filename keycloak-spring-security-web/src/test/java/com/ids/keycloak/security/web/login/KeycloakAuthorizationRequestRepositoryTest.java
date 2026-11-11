package com.ids.keycloak.security.web.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;

import jakarta.servlet.http.Cookie;

class KeycloakAuthorizationRequestRepositoryTest {

    static final Instant T0 = Instant.parse("2026-11-10T03:00:00Z");
    static final KeycloakKeyRing KEYS = new KeycloakKeyRing("k1", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes()));

    final AtomicReference<Instant> now = new AtomicReference<>(T0);
    final Clock clock = new Clock() {
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };
    final KeycloakAuthorizationRequestRepository repository = new KeycloakAuthorizationRequestRepository(
        new DefaultKeycloakCookieWriter("demo"), KEYS, new DefaultLoginReturnPathResolver(), clock);

    static OAuth2AuthorizationRequest authorizationRequest() {
        return OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("https://sso.kss.test/realms/kss-demo/protocol/openid-connect/auth")
            .clientId("demo")
            .redirectUri("https://api.kss.test:8443/login/oauth2/code/keycloak")
            .scopes(Set.of("openid"))
            .state("state-abc_123")
            .attributes(a -> {
                a.put("registration_id", "keycloak");
                a.put("code_verifier", "verifier-with-=&special+chars");
                a.put("nonce", "raw-nonce");
            })
            .additionalParameters(p -> {
                p.put("code_challenge", "challenge");
                p.put("code_challenge_method", "S256");
                p.put("nonce", "hashed-nonce");
            })
            .build();
    }

    /** 로그인 시작: ?return=…으로 저장하고 쓴 쿠키를 돌려준다. */
    Cookie save(String returnPath) {
        MockHttpServletRequest start = new MockHttpServletRequest("GET", "/oauth2/authorization/keycloak");
        if (returnPath != null) {
            start.setParameter("return", returnPath);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        repository.saveAuthorizationRequest(authorizationRequest(), start, response);
        String header = response.getHeader("Set-Cookie");
        assertThat(header).startsWith("__Host-demo_login=").contains("Max-Age=300", "HttpOnly", "Secure", "SameSite=Lax");
        return new Cookie("__Host-demo_login", header.substring("__Host-demo_login=".length(), header.indexOf(';')));
    }

    MockHttpServletRequest callback(Cookie cookie, String state) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        if (cookie != null) {
            request.setCookies(cookie);
        }
        request.setParameter("code", "code-1");
        request.setParameter("state", state);
        return request;
    }

    @Test
    @DisplayName("LOGIN-02 로그인 임시 정보를 암호화 쿠키(5분)에 두고, 쿠키에 state·verifier가 그대로 보이지 않는다")
    void savesEncryptedCookie() {
        Cookie cookie = save("/items/3");

        assertThat(cookie.getValue()).startsWith("k1.").doesNotContain("state-abc", "verifier", "items");
    }

    @Test
    @DisplayName("LOGIN-03 콜백에서 같은 인가 요청(state·PKCE verifier·nonce)을 돌려주고, 쿠키를 지우고, 돌아갈 경로를 넘긴다")
    void restoresOnCallback() {
        Cookie cookie = save("/items/3");
        MockHttpServletRequest request = callback(cookie, "state-abc_123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        OAuth2AuthorizationRequest restored = repository.removeAuthorizationRequest(request, response);

        OAuth2AuthorizationRequest original = authorizationRequest();
        assertThat(restored.getState()).isEqualTo(original.getState());
        assertThat(restored.getRedirectUri()).isEqualTo(original.getRedirectUri());
        assertThat(restored.getAuthorizationUri()).isEqualTo(original.getAuthorizationUri());
        assertThat(restored.getClientId()).isEqualTo("demo");
        assertThat(restored.getScopes()).containsExactly("openid");
        assertThat(restored.getAttributes()).isEqualTo(original.getAttributes());
        assertThat(restored.getAdditionalParameters()).isEqualTo(original.getAdditionalParameters());
        assertThat(response.getHeader("Set-Cookie")).startsWith("__Host-demo_login=;").contains("Max-Age=0");
        assertThat(request.getAttribute(KeycloakAuthorizationRequestRepository.RETURN_PATH_ATTRIBUTE)).isEqualTo("/items/3");
    }

    @Test
    @DisplayName("LOGIN-04 다른 사이트 return은 쿠키에 /로 담긴다")
    void unsafeReturnBecomesRoot() {
        MockHttpServletRequest request = callback(save("https://evil.example"), "state-abc_123");
        repository.removeAuthorizationRequest(request, new MockHttpServletResponse());
        assertThat(request.getAttribute(KeycloakAuthorizationRequestRepository.RETURN_PATH_ATTRIBUTE)).isEqualTo("/");
    }

    @Test
    @DisplayName("LOGIN-05 state가 다르거나, 쿠키가 없거나, 5분이 지났거나, 쿠키를 바꿨으면 돌려주지 않는다 (쿠키는 지운다)")
    void rejects() {
        Cookie cookie = save("/");

        assertThat(repository.removeAuthorizationRequest(callback(cookie, "other-state"), new MockHttpServletResponse())).isNull();
        assertThat(repository.removeAuthorizationRequest(callback(null, "state-abc_123"), new MockHttpServletResponse())).isNull();

        String value = cookie.getValue();
        char last = value.charAt(value.length() - 1);
        Cookie tampered = new Cookie(cookie.getName(), value.substring(0, value.length() - 1) + (last == 'A' ? 'B' : 'A'));
        assertThat(repository.removeAuthorizationRequest(callback(tampered, "state-abc_123"), new MockHttpServletResponse())).isNull();
        assertThat(repository.removeAuthorizationRequest(callback(new Cookie(cookie.getName(), "garbage"), "state-abc_123"),
            new MockHttpServletResponse())).isNull();

        now.set(T0.plus(Duration.ofMinutes(5)).plusSeconds(1));
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThat(repository.removeAuthorizationRequest(callback(cookie, "state-abc_123"), response)).isNull();
        assertThat(response.getHeader("Set-Cookie")).contains("Max-Age=0");

        now.set(T0.plus(Duration.ofMinutes(4)));
        assertThat(repository.removeAuthorizationRequest(callback(cookie, "state-abc_123"), new MockHttpServletResponse())).isNotNull();
    }

    @Test
    @DisplayName("다른 키 묶음(다른 앱)이 만든 쿠키는 풀리지 않는다")
    void otherKeysRejected() {
        Cookie cookie = save("/");
        KeycloakAuthorizationRequestRepository other = new KeycloakAuthorizationRequestRepository(new DefaultKeycloakCookieWriter("demo"),
            new KeycloakKeyRing("k1", Map.of("k1", "another-app-key-0123456789abcdef".getBytes())), new DefaultLoginReturnPathResolver(), clock);
        assertThat(other.removeAuthorizationRequest(callback(cookie, "state-abc_123"), new MockHttpServletResponse())).isNull();
    }
}
