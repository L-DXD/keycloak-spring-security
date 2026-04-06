package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakSecurityProperties}에 {@code csrf} 필드가 올바르게 구성되는지 검증합니다.
 */
class KeycloakSecurityPropertiesCsrfTest {

    @Nested
    class csrf_필드_기본값 {

        @Test
        void csrf_프로퍼티가_null이_아니다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThat(properties.getCsrf()).isNotNull();
        }

        @Test
        void csrf_기본값은_활성화_상태이다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThat(properties.getCsrf().isEnabled()).isTrue();
        }

        @Test
        void csrf_기본_면제경로는_비어있다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThat(properties.getCsrf().getIgnorePaths()).isEmpty();
        }
    }

    @Nested
    class 하위호환_확인 {

        @Test
        void 설정_없이_기존_프로퍼티들이_정상_초기화된다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            // 기존 프로퍼티들이 기본값으로 초기화되어야 함
            assertThat(properties.getBasicAuth()).isNotNull();
            assertThat(properties.getBasicAuth().isEnabled()).isFalse();
            assertThat(properties.getBearerToken()).isNotNull();
            assertThat(properties.getBearerToken().isEnabled()).isFalse();
            assertThat(properties.getRateLimit()).isNotNull();
            assertThat(properties.getRateLimit().isEnabled()).isFalse();

            // 새로 추가된 csrf 프로퍼티
            assertThat(properties.getCsrf()).isNotNull();
            assertThat(properties.getCsrf().isEnabled()).isTrue();
        }
    }

    @Nested
    class csrf_설정_조합 {

        @Test
        void csrf_비활성화_시_면제경로는_무시된다() {
            KeycloakCsrfProperties csrfProperties = new KeycloakCsrfProperties();
            csrfProperties.setEnabled(false);
            csrfProperties.setIgnorePaths(List.of("/api/**"));

            // enabled=false이면 ignorePaths는 실질적으로 의미 없음
            // (HttpConfigurer에서 csrf.disable()로 처리)
            assertThat(csrfProperties.isEnabled()).isFalse();
            assertThat(csrfProperties.getIgnorePaths()).isNotEmpty();
        }

        @Test
        void csrf_활성화_시_면제경로가_적용된다() {
            KeycloakCsrfProperties csrfProperties = new KeycloakCsrfProperties();
            csrfProperties.setEnabled(true);
            csrfProperties.setIgnorePaths(List.of("/api/**", "/webhook/**"));

            assertThat(csrfProperties.isEnabled()).isTrue();
            assertThat(csrfProperties.getIgnorePaths()).containsExactly("/api/**", "/webhook/**");
        }

        @Test
        void basicAuth_활성화와_csrf_활성화_조합() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();
            properties.getBasicAuth().setEnabled(true);
            properties.getCsrf().setEnabled(true);
            properties.getCsrf().setIgnorePaths(List.of("/api/**"));

            // Basic Auth + CSRF 활성화 조합에서 두 설정이 독립적으로 구성 가능
            assertThat(properties.getBasicAuth().isEnabled()).isTrue();
            assertThat(properties.getCsrf().isEnabled()).isTrue();
            assertThat(properties.getCsrf().getIgnorePaths()).containsExactly("/api/**");
        }
    }
}
