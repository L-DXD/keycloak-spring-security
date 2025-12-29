package com.ids.keycloak.security.starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakHttpConfigurer;
import com.ids.keycloak.security.web.servlet.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.web.servlet.KeycloakAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import lombok.extern.slf4j.Slf4j;

/**
 * Servlet 환경에서 Keycloak Spring Security를 위한 자동 설정 클래스.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
@Slf4j
public class KeycloakServletAutoConfiguration {

    public KeycloakServletAutoConfiguration() {
        log.info("Keycloak Spring Security: Servlet 환경 자동 설정이 활성화되었습니다.");
    }

    @Bean
    @ConditionalOnMissingBean(KeycloakAuthenticationEntryPoint.class)
    public KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint(ObjectMapper objectMapper) {
        log.info("Keycloak Spring Security: KeycloakAuthenticationEntryPoint 빈이 등록되었습니다.");
        return new KeycloakAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(KeycloakAccessDeniedHandler.class)
    public KeycloakAccessDeniedHandler keycloakAccessDeniedHandler(ObjectMapper objectMapper) {
        log.info("Keycloak Spring Security: KeycloakAccessDeniedHandler 빈이 등록되었습니다.");
        return new KeycloakAccessDeniedHandler(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain keycloakSecurityFilterChain(
            HttpSecurity http,
            KeycloakAuthenticationEntryPoint authenticationEntryPoint,
            KeycloakAccessDeniedHandler accessDeniedHandler
    ) throws Exception {

        // 인증, 인가 실패 시 처리할 커스텀 예외 핸들러 등록
        http.exceptionHandling(customizer -> customizer
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
        );

        // Keycloak 관련 설정(필터 등) 적용
        http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());

        log.info("Keycloak Spring Security: Servlet SecurityFilterChain 빈이 등록되었습니다.");
        return http.build();
    }
}