package com.ids.keycloak.security.web.error;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.ids.keycloak.security.error.KeycloakErrorCode;

class KeycloakErrorResponseWriterTest {

    private final KeycloakErrorResponseWriter writer = new KeycloakErrorResponseWriter("keycloak");

    @Test
    @DisplayName("LOGIN-01 401 본문에 오류 코드와 로그인 주소가 있다 (context-path 포함)")
    void unauthorized() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/portal/api/me");
        request.setContextPath("/portal");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new KeycloakAuthenticationEntryPoint(writer).commence(request, response, null);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString()).isEqualTo(
            "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"로그인이 필요합니다.\",\"loginUrl\":\"/portal/oauth2/authorization/keycloak\"}");
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
    }

    @Test
    @DisplayName("403·503에는 로그인 주소를 넣지 않는다")
    void forbiddenAndUnavailable() throws Exception {
        MockHttpServletResponse forbidden = new MockHttpServletResponse();
        new KeycloakAccessDeniedHandler(writer).handle(new MockHttpServletRequest(), forbidden, null);
        assertThat(forbidden.getStatus()).isEqualTo(403);
        assertThat(forbidden.getContentAsString()).contains("\"code\":\"ACCESS_DENIED\"").doesNotContain("loginUrl");

        MockHttpServletResponse unavailable = new MockHttpServletResponse();
        writer.write(new MockHttpServletRequest(), unavailable, KeycloakErrorCode.KEYCLOAK_UNAVAILABLE);
        assertThat(unavailable.getStatus()).isEqualTo(503);
        assertThat(unavailable.getContentAsString()).contains("KEYCLOAK_UNAVAILABLE");
    }

    @Test
    @DisplayName("JSON 문자열은 따옴표·역슬래시·제어 문자·<를 이스케이프한다")
    void quote() {
        assertThat(KeycloakErrorResponseWriter.quote("a\"b\\c\n<script>\u0001")).isEqualTo("\"a\\\"b\\\\c\\n\\u003cscript>\\u0001\"");
    }
}
