package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.filter.KeycloakAuthenticationFilter;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.web.servlet.KeycloakAccessDeniedHandler;
import com.sd.KeycloakClient.factory.KeycloakClient;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

/**
 * Keycloak 인증에 필요한 모든 핵심 설정을 {@link HttpSecurity}에 등록하는
 * {@link AbstractHttpConfigurer} 구현체입니다.
 * 이 Configurer는 인증 필터, 프로바이더, 예외 핸들러, SecurityContext 저장소를 모두 설정합니다.
 */
public final class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

    private KeycloakHttpConfigurer() {
    }

    /**
     * Configurer 인스턴스를 생성하는 정적 팩토리 메서드입니다.
     */
    public static KeycloakHttpConfigurer keycloak() {
        return new KeycloakHttpConfigurer();
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        // ApplicationContext에서 Provider 생성에 필요한 Bean들을 조회합니다.
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        JwtDecoder jwtDecoder = context.getBean(JwtDecoder.class);
        KeycloakClient keycloakClient = context.getBean(KeycloakClient.class);
        ClientRegistrationRepository clientRegistrationRepository = context.getBean(ClientRegistrationRepository.class);

        // 조회한 Bean들로 Provider를 생성하고 HttpSecurity에 등록합니다.
        KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider(
            jwtDecoder,
            keycloakClient,
            clientRegistrationRepository
        );
        http.authenticationProvider(provider);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        
        // ApplicationContext에서 Filter와 Handler 생성에 필요한 Bean들을 조회합니다.
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2AuthorizedClientRepository authorizedClientRepository = context.getBean(OAuth2AuthorizedClientRepository.class);
        ClientRegistrationRepository clientRegistrationRepository = context.getBean(ClientRegistrationRepository.class);
        ObjectMapper objectMapper = context.getBean(ObjectMapper.class);
        KeycloakAuthenticationEntryPoint authenticationEntryPoint = context.getBean(KeycloakAuthenticationEntryPoint.class);
        KeycloakAccessDeniedHandler accessDeniedHandler = context.getBean(KeycloakAccessDeniedHandler.class);

        // 1. 예외 처리기 설정
        http.exceptionHandling(customizer -> customizer
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(accessDeniedHandler)
        );

        // 2. SecurityContext 저장소 설정
        http.securityContext(customizer -> customizer
            .securityContextRepository(new HttpSessionSecurityContextRepository())
        );

        // 3. 커스텀 인증 필터 생성 및 등록
        KeycloakAuthenticationFilter filter = new KeycloakAuthenticationFilter(
            authenticationManager,
            authorizedClientRepository,
            clientRegistrationRepository,
            objectMapper
        );
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
