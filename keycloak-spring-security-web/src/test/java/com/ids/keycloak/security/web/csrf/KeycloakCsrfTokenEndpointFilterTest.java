package com.ids.keycloak.security.web.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

class KeycloakCsrfTokenEndpointFilterTest {

    final KeycloakCsrfTokenEndpointFilter filter = new KeycloakCsrfTokenEndpointFilter("/api/csrf");

    MockHttpServletRequest request(String method, String contextPath, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
        request.setContextPath(contextPath);
        request.setAttribute(CsrfToken.class.getName(), new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "k1.abc.def"));
        return request;
    }

    @Test
    @DisplayName("CSRF-01 GET /api/csrf → 200, 헤더 이름·칸 이름·토큰 JSON, 캐시하지 않음")
    void returnsToken() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request("GET", "", "/api/csrf"), response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString())
            .isEqualTo("{\"headerName\":\"X-XSRF-TOKEN\",\"parameterName\":\"_csrf\",\"token\":\"k1.abc.def\"}");
    }

    @Test
    @DisplayName("context-path 뒤의 경로로 맞춘다")
    void contextPath() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request("GET", "/app", "/app/api/csrf"), response, new MockFilterChain());

        assertThat(response.getContentAsString()).contains("\"token\":\"k1.abc.def\"");
    }

    @Test
    @DisplayName("다른 경로, GET이 아닌 요청, CSRF가 꺼진 체인(토큰 없음)은 그냥 넘긴다")
    void passesOtherRequests() throws Exception {
        for (MockHttpServletRequest request : new MockHttpServletRequest[] {
            request("GET", "", "/api/me"), request("POST", "", "/api/csrf"), new MockHttpServletRequest("GET", "/api/csrf")}) {
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(request, new MockHttpServletResponse(), chain);
            assertThat(chain.getRequest()).isNotNull();
        }
    }
}
