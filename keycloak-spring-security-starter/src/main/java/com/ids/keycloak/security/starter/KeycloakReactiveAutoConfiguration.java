package com.ids.keycloak.security.starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.web.reactive.KeycloakServerAccessDeniedHandler;
import com.ids.keycloak.security.web.reactive.KeycloakServerAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import lombok.extern.slf4j.Slf4j;

/**
 * Reactive 환경에서 Keycloak Spring Security를 위한 자동 설정 클래스.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(SecurityWebFilterChain.class)
@Slf4j
public class KeycloakReactiveAutoConfiguration {

    public KeycloakReactiveAutoConfiguration() {
        log.info("Keycloak Spring Security: Reactive 환경 자동 설정이 활성화되었습니다.");
    }

    @Bean
    @ConditionalOnMissingBean(KeycloakServerAuthenticationEntryPoint.class)
    public KeycloakServerAuthenticationEntryPoint keycloakServerAuthenticationEntryPoint(ObjectMapper objectMapper) {
        log.info("Keycloak Spring Security: KeycloakServerAuthenticationEntryPoint 빈이 등록되었습니다.");
        return new KeycloakServerAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(KeycloakServerAccessDeniedHandler.class)
    public KeycloakServerAccessDeniedHandler keycloakServerAccessDeniedHandler(ObjectMapper objectMapper) {
        log.info("Keycloak Spring Security: KeycloakServerAccessDeniedHandler 빈이 등록되었습니다.");
        return new KeycloakServerAccessDeniedHandler(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    public SecurityWebFilterChain keycloakSecurityWebFilterChain(
            ServerHttpSecurity http,
            KeycloakServerAuthenticationEntryPoint authenticationEntryPoint,
            KeycloakServerAccessDeniedHandler accessDeniedHandler
    ) {
        // 인증, 인가 실패 시 처리할 커스텀 예외 핸들러 등록
        http.exceptionHandling(customizer -> customizer
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
        );

        // TODO: 추후 Reactive 용 Configurer 구현 시 추가
        // http.with(KeycloakWebFluxConfigurer.keycloak(), Customizer.withDefaults());

        log.info("Keycloak Spring Security: Reactive SecurityWebFilterChain 빈이 등록되었습니다.");
        return http.build();
    }
}
