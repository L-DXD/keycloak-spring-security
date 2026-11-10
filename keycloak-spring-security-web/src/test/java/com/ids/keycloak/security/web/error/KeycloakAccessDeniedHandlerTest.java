package com.ids.keycloak.security.web.error;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

class KeycloakAccessDeniedHandlerTest {

    final KeycloakAccessDeniedHandler handler = new KeycloakAccessDeniedHandler(new KeycloakErrorResponseWriter("keycloak"));

    String code(AccessDeniedException e) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.handle(new MockHttpServletRequest("POST", "/api/items"), response, e);
        assertThat(response.getStatus()).isEqualTo(403);
        return response.getContentAsString();
    }

    @Test
    @DisplayName("CSRF 토큰이 없거나 틀리면 403 INVALID_CSRF_TOKEN (화면이 토큰을 다시 받게), 그 밖은 ACCESS_DENIED")
    void codes() throws Exception {
        assertThat(code(new MissingCsrfTokenException(null))).contains("\"code\":\"INVALID_CSRF_TOKEN\"");
        assertThat(code(new InvalidCsrfTokenException(new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "a"), "b")))
            .contains("\"code\":\"INVALID_CSRF_TOKEN\"");
        assertThat(code(new AccessDeniedException("권한 없음"))).contains("\"code\":\"ACCESS_DENIED\"");
    }
}
