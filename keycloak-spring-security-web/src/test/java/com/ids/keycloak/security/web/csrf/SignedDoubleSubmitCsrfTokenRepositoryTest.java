package com.ids.keycloak.security.web.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;

import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;

import jakarta.servlet.http.Cookie;

class SignedDoubleSubmitCsrfTokenRepositoryTest {

    final KeycloakCsrfTokenSigner signer = new KeycloakCsrfTokenSigner(new KeycloakKeyRing("k1",
        Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes())));
    final SignedDoubleSubmitCsrfTokenRepository repository = new SignedDoubleSubmitCsrfTokenRepository(signer,
        new DefaultKeycloakCookieWriter("demo"), Duration.ofHours(12));

    static MockHttpServletRequest request(Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/items");
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        return request;
    }

    @Test
    @DisplayName("csrf 쿠키의 토큰이 이 요청의 sid로 서명돼 있으면 그 토큰을 쓴다 (헤더 X-XSRF-TOKEN, 칸 _csrf)")
    void loadsTokenSignedForSid() {
        String sid = SessionIds.newSid();
        String token = signer.create(sid);

        CsrfToken loaded = repository.loadToken(request(new Cookie("__Host-demo_sid", sid), new Cookie("__Host-demo_csrf", token)));

        assertThat(loaded.getToken()).isEqualTo(token);
        assertThat(loaded.getHeaderName()).isEqualTo("X-XSRF-TOKEN");
        assertThat(loaded.getParameterName()).isEqualTo("_csrf");
    }

    @Test
    @DisplayName("CSRF-04 다른 sid로 서명된 csrf 쿠키(다른 사람 것을 심음)는 쓰지 않는다")
    void ignoresTokenSignedForOtherSid() {
        String mine = SessionIds.newSid();
        String someoneElses = signer.create(SessionIds.newSid());

        assertThat(repository.loadToken(request(new Cookie("__Host-demo_sid", mine), new Cookie("__Host-demo_csrf", someoneElses))))
            .isNull();
    }

    @Test
    @DisplayName("CSRF-06 로그인 전 토큰(sid 없음)은 로그인 뒤(sid 있음)에 쓰지 않는다")
    void anonymousTokenIsNotValidAfterLogin() {
        String anonymous = repository.generateToken(request()).getToken();

        assertThat(repository.loadToken(request(new Cookie("__Host-demo_csrf", anonymous)))).isNotNull();
        assertThat(repository.loadToken(request(new Cookie("__Host-demo_sid", SessionIds.newSid()), new Cookie("__Host-demo_csrf", anonymous))))
            .isNull();
    }

    @Test
    @DisplayName("새 토큰은 sid에 묶여 만들어지고, 저장하면 csrf 쿠키(HttpOnly, 절대 상한 수명)를 쓴다. null 저장은 쿠키를 지운다")
    void generateSaveAndClear() {
        String sid = SessionIds.newSid();
        MockHttpServletRequest request = request(new Cookie("__Host-demo_sid", sid));
        CsrfToken token = repository.generateToken(request);
        MockHttpServletResponse response = new MockHttpServletResponse();

        repository.saveToken(token, request, response);
        repository.saveToken(null, request, response);

        assertThat(signer.matches(sid, token.getToken())).isTrue();
        assertThat(response.getHeaders("Set-Cookie")).satisfiesExactly(
            c -> assertThat(c).startsWith("__Host-demo_csrf=" + token.getToken() + ";").contains("Max-Age=43200").contains("HttpOnly"),
            c -> assertThat(c).startsWith("__Host-demo_csrf=;").contains("Max-Age=0"));
    }

    @Test
    @DisplayName("csrf 쿠키가 없거나 모양이 틀리면 null (Spring이 새로 만든다)")
    void missingOrMalformed() {
        assertThat(repository.loadToken(request())).isNull();
        assertThat(repository.loadToken(request(new Cookie("__Host-demo_csrf", "not.a.token")))).isNull();
    }
}
