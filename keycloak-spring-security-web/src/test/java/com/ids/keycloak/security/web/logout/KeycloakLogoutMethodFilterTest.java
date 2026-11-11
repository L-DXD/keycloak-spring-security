package com.ids.keycloak.security.web.logout;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;

class KeycloakLogoutMethodFilterTest {

    final KeycloakLogoutMethodFilter filter = new KeycloakLogoutMethodFilter(PathPatternRequestMatcher.withDefaults().matcher("/logout"),
        new KeycloakErrorResponseWriter("keycloak"));

    @ParameterizedTest(name = "LOGOUT-03 {0} /logout → 405, Allow: POST, 로그아웃하지 않는다")
    @CsvSource({"GET", "HEAD", "PUT", "DELETE"})
    void notPost(String method) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(method, "/logout"), response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(405);
        assertThat(response.getHeader("Allow")).isEqualTo("POST");
        if (!"HEAD".equals(method)) {
            assertThat(response.getContentAsString()).contains("\"code\":\"METHOD_NOT_ALLOWED\"");
        }
    }

    @ParameterizedTest(name = "{0} {1}은 그냥 넘긴다")
    @CsvSource({"POST, /logout", "GET, /api/me", "GET, /logged-out"})
    void passes(String method, String path) throws Exception {
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(method, path), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
    }
}
