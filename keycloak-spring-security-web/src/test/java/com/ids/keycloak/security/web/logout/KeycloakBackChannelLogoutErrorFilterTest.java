package com.ids.keycloak.security.web.logout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import jakarta.servlet.FilterChain;

class KeycloakBackChannelLogoutErrorFilterTest {

    final KeycloakBackChannelLogoutErrorFilter filter = new KeycloakBackChannelLogoutErrorFilter(
        PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/logout/connect/back-channel/{registrationId}"));

    static FilterChain throwing(RuntimeException e) {
        return (req, res) -> {
            throw e;
        };
    }

    @Test
    @DisplayName("BCL-02 필수 클레임이 빠져 Spring이 던진 예외(원인 IllegalArgumentException)는 400 invalid_request")
    void malformedTokenIs400() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("POST", "/logout/connect/back-channel/keycloak"), response,
            throwing(new AuthenticationServiceException("events cannot be null", new IllegalArgumentException("events cannot be null"))));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("\"error\":\"invalid_request\"").contains("events");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    @DisplayName("다른 원인(JWKS를 못 받음 등)이나 다른 주소의 예외는 그대로 던진다")
    void othersPropagate() {
        AuthenticationServiceException jwks = new AuthenticationServiceException("JWKS", new IllegalStateException("down"));
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest("POST", "/logout/connect/back-channel/keycloak"),
            new MockHttpServletResponse(), throwing(jwks))).isSameAs(jwks);

        AuthenticationServiceException elsewhere = new AuthenticationServiceException("x", new IllegalArgumentException());
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest("POST", "/api/items"), new MockHttpServletResponse(),
            throwing(elsewhere))).isSameAs(elsewhere);
    }
}
