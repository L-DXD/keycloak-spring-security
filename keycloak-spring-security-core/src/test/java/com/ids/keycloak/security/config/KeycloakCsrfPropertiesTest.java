package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class KeycloakCsrfPropertiesTest {

    @Nested
    class 기본값_검증 {

        @Test
        void 기본_enabled는_true이다() {
            KeycloakCsrfProperties properties = new KeycloakCsrfProperties();

            assertThat(properties.isEnabled()).isTrue();
        }

        @Test
        void 기본_ignorePaths는_빈_리스트이다() {
            KeycloakCsrfProperties properties = new KeycloakCsrfProperties();

            assertThat(properties.getIgnorePaths()).isNotNull();
            assertThat(properties.getIgnorePaths()).isEmpty();
        }
    }

    @Nested
    class Setter_검증 {

        @Test
        void enabled를_false로_변경할_수_있다() {
            KeycloakCsrfProperties properties = new KeycloakCsrfProperties();
            properties.setEnabled(false);

            assertThat(properties.isEnabled()).isFalse();
        }

        @Test
        void ignorePaths를_설정할_수_있다() {
            KeycloakCsrfProperties properties = new KeycloakCsrfProperties();
            properties.setIgnorePaths(List.of("/api/**", "/webhook/**"));

            assertThat(properties.getIgnorePaths()).containsExactly("/api/**", "/webhook/**");
        }

        @Test
        void ignorePaths에_경로를_추가할_수_있다() {
            KeycloakCsrfProperties properties = new KeycloakCsrfProperties();
            properties.getIgnorePaths().add("/api/**");
            properties.getIgnorePaths().add("/webhook/**");

            assertThat(properties.getIgnorePaths()).hasSize(2);
            assertThat(properties.getIgnorePaths()).containsExactly("/api/**", "/webhook/**");
        }
    }
}
