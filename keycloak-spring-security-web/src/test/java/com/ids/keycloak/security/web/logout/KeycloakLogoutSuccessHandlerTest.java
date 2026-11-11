package com.ids.keycloak.security.web.logout;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.ids.keycloak.security.web.logout.KeycloakLogoutHandler.Result;

class KeycloakLogoutSuccessHandlerTest {

    static final URI FRONTEND = URI.create("https://app.example.com/logged-out");
    static final URI END_SESSION = URI.create("https://sso.example.com/realms/demo/protocol/openid-connect/logout");

    final KeycloakLogoutSuccessHandler handler = new KeycloakLogoutSuccessHandler(FRONTEND, END_SESSION, "demo");

    MockHttpServletResponse send(KeycloakLogoutSuccessHandler handler, Result result) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        if (result != null) {
            request.setAttribute(KeycloakLogoutHandler.RESULT_ATTRIBUTE, result);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onLogoutSuccess(request, response, null);
        return response;
    }

    @Test
    @DisplayName("LOGOUT-01·05 Keycloak 로그아웃이 됐거나 세션이 없었으면 화면 로그아웃 주소로 302")
    void frontend() throws Exception {
        for (Result result : new Result[] {Result.KEYCLOAK_LOGGED_OUT, Result.NO_SESSION, null}) {
            MockHttpServletResponse response = send(handler, result);
            assertThat(response.getStatus()).isEqualTo(302);
            assertThat(response.getHeader("Location")).isEqualTo(FRONTEND.toString());
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        }
    }

    @Test
    @DisplayName("LOGOUT-02 Keycloak 로그아웃을 못 했으면 OIDC 로그아웃 주소: client_id·post_logout_redirect_uri·state, id_token_hint 없음")
    void oidcLogout() throws Exception {
        String first = send(handler, Result.KEYCLOAK_FAILED).getHeader("Location");
        String second = send(handler, Result.KEYCLOAK_FAILED).getHeader("Location");

        UriComponents uri = UriComponentsBuilder.fromUriString(first).build();
        assertThat(first).startsWith(END_SESSION + "?");
        assertThat(uri.getQueryParams().getFirst("client_id")).isEqualTo("demo");
        assertThat(URI.create(first).getQuery()).contains("post_logout_redirect_uri=" + FRONTEND);
        assertThat(uri.getQueryParams().getFirst("state")).hasSizeGreaterThanOrEqualTo(20);
        assertThat(uri.getQueryParams()).doesNotContainKey("id_token_hint");
        assertThat(first).as("state는 매번 다르다").isNotEqualTo(second);
    }

    @Test
    @DisplayName("OIDC 로그아웃 주소를 모르면(설명 문서에 없음) 화면 로그아웃 주소로")
    void noEndSessionEndpoint() throws Exception {
        assertThat(send(new KeycloakLogoutSuccessHandler(FRONTEND, null, "demo"), Result.KEYCLOAK_FAILED).getHeader("Location"))
            .isEqualTo(FRONTEND.toString());
    }
}
