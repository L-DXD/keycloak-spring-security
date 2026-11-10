package com.ids.keycloak.security.web.login;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class DefaultLoginReturnPathResolverTest {

    private final DefaultLoginReturnPathResolver resolver = new DefaultLoginReturnPathResolver();

    @Test
    @DisplayName("상대 경로는 그대로 받는다 (쿼리·# 포함)")
    void acceptsRelativePaths() {
        for (String ok : new String[] {"/", "/items/3", "/items?tab=2&sort=name", "/app#/settings", "/%2F%2Fstill-same-host"}) {
            assertThat(resolver.sanitize(ok)).isEqualTo(ok);
        }
    }

    @Test
    @DisplayName("LOGIN-04 다른 사이트로 보내는 값은 모두 / (https://, //, /\\, javascript:, 공백·제어 문자, 너무 긴 값)")
    void rejectsOpenRedirects() {
        for (String bad : new String[] {"https://evil.example", "//evil.example", "/\\evil.example", "\\\\evil.example", "javascript:alert(1)",
            "evil.example", "/items\n/x", "/items x", "/\u0000", "/" + "a".repeat(2048), "", null}) {
            assertThat(resolver.sanitize(bad)).as(String.valueOf(bad)).isEqualTo("/");
        }
    }

    @Test
    @DisplayName("요청의 return 파라미터를 읽는다")
    void readsParameter() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("return", "/items/3");
        assertThat(resolver.resolve(request)).isEqualTo("/items/3");
        assertThat(resolver.resolve(new MockHttpServletRequest())).isEqualTo("/");
        assertThat(new DefaultLoginReturnPathResolver("next").resolve(request)).isEqualTo("/");
    }
}
