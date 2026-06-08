package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link KeycloakSecurityMatcherFactory}가 include/exclude 설정을 올바른 매칭 동작으로 변환하는지 검증합니다.
 * <p>
 * 이 매처는 Keycloak SecurityFilterChain의 담당 경로를 결정하므로, Fail-Open 방지 설계의 핵심 로직입니다.
 * </p>
 */
class KeycloakSecurityMatcherFactoryTest {

    private static MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        // AntPathRequestMatcher는 servletPath 기반으로 매칭하므로 명시적으로 설정
        request.setServletPath(uri);
        return request;
    }

    private static boolean matches(RequestMatcher matcher, String uri) {
        HttpServletRequest request = request(uri);
        return matcher.matches(request);
    }

    private static KeycloakMatcherProperties props(List<String> include, List<String> exclude) {
        KeycloakMatcherProperties p = new KeycloakMatcherProperties();
        p.setInclude(include);
        p.setExclude(exclude);
        return p;
    }

    @Nested
    @DisplayName("기본값(include=/**, exclude 없음)")
    class DefaultMatcher {

        @Test
        @DisplayName("모든 경로를 담당한다")
        void matchesEverything() {
            RequestMatcher matcher = KeycloakSecurityMatcherFactory.from(new KeycloakMatcherProperties());

            assertThat(matches(matcher, "/")).isTrue();
            assertThat(matches(matcher, "/api/users")).isTrue();
            assertThat(matches(matcher, "/actuator/health")).isTrue();
            assertThat(matches(matcher, "/anything/deep/path")).isTrue();
        }
    }

    @Nested
    @DisplayName("exclude 지정 시 (include=/**, exclude=/actuator/**)")
    class WithExclude {

        private final RequestMatcher matcher =
            KeycloakSecurityMatcherFactory.from(props(List.of("/**"), List.of("/actuator/**")));

        @Test
        @DisplayName("제외 경로는 Keycloak 체인이 담당하지 않는다 (다른 체인으로 위임)")
        void excludedPathNotMatched() {
            assertThat(matches(matcher, "/actuator/health")).isFalse();
            assertThat(matches(matcher, "/actuator/info")).isFalse();
        }

        @Test
        @DisplayName("그 외 경로는 Keycloak 체인이 담당한다")
        void otherPathsMatched() {
            assertThat(matches(matcher, "/api/users")).isTrue();
            assertThat(matches(matcher, "/")).isTrue();
        }
    }

    @Nested
    @DisplayName("복수 include / 복수 exclude")
    class MultiplePatterns {

        @Test
        @DisplayName("include 목록 중 하나라도 매칭되면 담당한다")
        void multipleIncludes() {
            RequestMatcher matcher =
                KeycloakSecurityMatcherFactory.from(props(List.of("/api/**", "/admin/**"), List.of()));

            assertThat(matches(matcher, "/api/users")).isTrue();
            assertThat(matches(matcher, "/admin/dashboard")).isTrue();
            assertThat(matches(matcher, "/public/home")).isFalse();
        }

        @Test
        @DisplayName("exclude 목록 중 하나라도 매칭되면 제외한다")
        void multipleExcludes() {
            RequestMatcher matcher =
                KeycloakSecurityMatcherFactory.from(props(List.of("/**"), List.of("/actuator/**", "/public/**")));

            assertThat(matches(matcher, "/actuator/health")).isFalse();
            assertThat(matches(matcher, "/public/home")).isFalse();
            assertThat(matches(matcher, "/api/users")).isTrue();
        }
    }
}
