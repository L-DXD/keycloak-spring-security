package com.ids.keycloak.security.web.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import com.ids.keycloak.security.web.cors.KeycloakCors;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;

class KeycloakOriginFilterTest {

    final KeycloakOriginFilter filter = new KeycloakOriginFilter(
        KeycloakCors.source(KeycloakCors.configuration("https://app.kss.test", "X-Background")),
        PathPatternRequestMatcher.withDefaults().matcher("/logout/connect/back-channel/**"),
        new KeycloakErrorResponseWriter("keycloak"));

    record Result(int status, boolean passed, String body) {
    }

    Result send(String method, String path, String origin, String referer) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (origin != null) {
            request.addHeader("Origin", origin);
        }
        if (referer != null) {
            request.addHeader("Referer", referer);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        return new Result(response.getStatus(), chain.getRequest() != null, response.getContentAsString());
    }

    @Test
    @DisplayName("화면 Origin의 POST는 통과")
    void allowedOrigin() throws Exception {
        assertThat(send("POST", "/api/items", "https://app.kss.test", null).passed()).isTrue();
    }

    @ParameterizedTest(name = "CSRF-05 Origin={0}, Referer={1} → 403 ORIGIN_NOT_ALLOWED")
    @CsvSource(nullValues = "-", value = {
        "https://evil.kss.test, -",
        "-, -",
        "null, -",
        "https://app.kss.test.evil.test, -",
        "http://app.kss.test, -",
        "https://app.kss.test:8443, -",
        "-, https://evil.kss.test/page",
        "-, not a url",
        "https://evil.kss.test, https://app.kss.test/items"
    })
    void rejected(String origin, String referer) throws Exception {
        Result result = send("POST", "/api/items", origin, referer);

        assertThat(result.passed()).isFalse();
        assertThat(result.status()).isEqualTo(403);
        assertThat(result.body()).contains("\"code\":\"ORIGIN_NOT_ALLOWED\"");
    }

    @Test
    @DisplayName("CSRF-05 Origin이 없고 Referer가 화면 주소면 통과")
    void refererFallback() throws Exception {
        assertThat(send("POST", "/api/items", null, "https://app.kss.test/items/3?x=1").passed()).isTrue();
    }

    @ParameterizedTest(name = "{0}은 상태를 바꾸지 않으므로 Origin을 보지 않는다")
    @CsvSource({"GET", "HEAD", "OPTIONS", "TRACE"})
    void safeMethods(String method) throws Exception {
        assertThat(send(method, "/api/me", "https://evil.kss.test", null).passed()).isTrue();
    }

    @Test
    @DisplayName("back-channel 로그아웃(Keycloak이 서버에서 부름)은 Origin 없이 통과")
    void backChannelExcluded() throws Exception {
        assertThat(send("POST", "/logout/connect/back-channel/keycloak", null, null).passed()).isTrue();
    }

    @ParameterizedTest(name = "PUT·PATCH·DELETE도 막는다: {0}")
    @CsvSource({"PUT", "PATCH", "DELETE"})
    void otherUnsafeMethods(String method) throws Exception {
        assertThat(send(method, "/api/items/1", "https://evil.kss.test", null).status()).isEqualTo(403);
        assertThat(send(method, "/api/items/1", "https://app.kss.test", null).passed()).isTrue();
    }
}
