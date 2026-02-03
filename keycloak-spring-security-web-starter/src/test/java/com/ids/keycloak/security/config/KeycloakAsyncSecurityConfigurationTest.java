package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakAsyncProperties} 단위 테스트입니다.
 */
class KeycloakAsyncSecurityConfigurationTest {

    @Nested
    @DisplayName("KeycloakAsyncProperties 기본값")
    class DefaultPropertiesTest {

        @Test
        @DisplayName("기본값이 올바르게 설정됨")
        void defaultValuesAreCorrect() {
            // Given
            KeycloakAsyncProperties properties = new KeycloakAsyncProperties();

            // Then
            assertThat(properties.isSecurityContextPropagation())
                .as("기본값: security-context-propagation=false")
                .isFalse();
            assertThat(properties.getCorePoolSize())
                .as("기본값: core-pool-size=10")
                .isEqualTo(10);
            assertThat(properties.getMaxPoolSize())
                .as("기본값: max-pool-size=50")
                .isEqualTo(50);
            assertThat(properties.getQueueCapacity())
                .as("기본값: queue-capacity=100")
                .isEqualTo(100);
            assertThat(properties.getThreadNamePrefix())
                .as("기본값: thread-name-prefix=keycloak-async-")
                .isEqualTo("keycloak-async-");
        }

        @Test
        @DisplayName("값 설정이 올바르게 동작함")
        void settersWorkCorrectly() {
            // Given
            KeycloakAsyncProperties properties = new KeycloakAsyncProperties();

            // When
            properties.setSecurityContextPropagation(true);
            properties.setCorePoolSize(5);
            properties.setMaxPoolSize(20);
            properties.setQueueCapacity(50);
            properties.setThreadNamePrefix("custom-async-");

            // Then
            assertThat(properties.isSecurityContextPropagation()).isTrue();
            assertThat(properties.getCorePoolSize()).isEqualTo(5);
            assertThat(properties.getMaxPoolSize()).isEqualTo(20);
            assertThat(properties.getQueueCapacity()).isEqualTo(50);
            assertThat(properties.getThreadNamePrefix()).isEqualTo("custom-async-");
        }
    }

    @Nested
    @DisplayName("KeycloakSecurityProperties와 통합")
    class IntegrationWithSecurityPropertiesTest {

        @Test
        @DisplayName("KeycloakSecurityProperties에서 async 프로퍼티 접근 가능")
        void asyncPropertiesAccessibleFromSecurityProperties() {
            // Given
            KeycloakSecurityProperties securityProperties = new KeycloakSecurityProperties();

            // Then
            assertThat(securityProperties.getAsync())
                .as("async 프로퍼티가 null이 아니어야 함")
                .isNotNull();
            assertThat(securityProperties.getAsync().isSecurityContextPropagation())
                .as("기본값은 false")
                .isFalse();
        }

        @Test
        @DisplayName("async 프로퍼티 값 변경이 반영됨")
        void asyncPropertiesModificationReflected() {
            // Given
            KeycloakSecurityProperties securityProperties = new KeycloakSecurityProperties();

            // When
            securityProperties.getAsync().setSecurityContextPropagation(true);
            securityProperties.getAsync().setCorePoolSize(15);

            // Then
            assertThat(securityProperties.getAsync().isSecurityContextPropagation()).isTrue();
            assertThat(securityProperties.getAsync().getCorePoolSize()).isEqualTo(15);
        }
    }
}
