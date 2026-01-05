package com.ids.keycloak.security.test.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.web.servlet.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.web.servlet.KeycloakAuthenticationEntryPoint;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

@SpringBootApplication
@Slf4j
public class ServletApp {
    public static void main(String[] args) {
        SpringApplication.run(ServletApp.class, args);
    }



    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public KeycloakAuthenticationEntryPoint customAuthenticationEntryPoint(ObjectMapper objectMapper) {
        log.info("Custom KeycloakAuthenticationEntryPoint 빈이 등록되었습니다.");
        return new KeycloakAuthenticationEntryPoint(objectMapper) {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                log.warn("Custom Authentication Entry Point triggered: {}", authException.getMessage());
                super.commence(request, response, authException);
            }
        };
    }

    @Bean
    public KeycloakAccessDeniedHandler customAccessDeniedHandler(ObjectMapper objectMapper) {
        log.info("Custom KeycloakAccessDeniedHandler 빈이 등록되었습니다.");
        return new KeycloakAccessDeniedHandler(objectMapper) {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                log.warn("Custom Access Denied Handler triggered: {}", accessDeniedException.getMessage());
                super.handle(request, response, accessDeniedException);
            }
        };
    }
}
