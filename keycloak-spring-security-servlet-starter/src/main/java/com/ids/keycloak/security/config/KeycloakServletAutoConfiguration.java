package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.filter.KeycloakAuthenticationFilter;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.web.servlet.KeycloakAccessDeniedHandler;
import com.sd.KeycloakClient.config.AbstractKeycloakConfig;
import com.sd.KeycloakClient.config.ClientConfiguration;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

/**
 * Keycloak Spring Security의 Servlet 환경 자동 설정을 담당하는 진입점입니다.
 * 역할별로 분리된 내부 설정 클래들을 Import 합니다.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(CookieProperties.class)
@Import({
    KeycloakServletAutoConfiguration.KeycloakInfrastructureConfiguration.class,
    KeycloakServletAutoConfiguration.KeycloakAuthenticationConfiguration.class,
    KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration.class
})
@Slf4j
public class KeycloakServletAutoConfiguration {
    public KeycloakServletAutoConfiguration() {
        log.info("Keycloak Spring Security: Servlet 환경 자동 설정이 활성화되었습니다.");
    }
    
    @Configuration(proxyBeanMethods = false)
    @RequiredArgsConstructor
    static class CookieUtilInitializer {
        private final CookieProperties cookieProperties;

        @PostConstruct
        public void init() {
            log.debug("CookieUtil에 CookieProperties를 주입합니다.");
            CookieUtil.setProperties(cookieProperties);
        }
    }

    /**
     * 기반 시설 (Infrastructure) 관련 Bean 설정
     */
    @Configuration(proxyBeanMethods = false)
    @Slf4j
    protected static class KeycloakInfrastructureConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public ObjectMapper keycloakObjectMapper() {
            log.debug("지원 Bean을 등록합니다: [ObjectMapper]");
            return new ObjectMapper();
        }

        @Bean
        @ConditionalOnMissingBean
        public RestTemplate keycloakRestTemplate() {
            log.debug("지원 Bean을 등록합니다: [RestTemplate]");
            return new RestTemplate();
        }

        @Configuration(proxyBeanMethods = false)
        @Getter
        @Slf4j
        protected static class KeycloakConfig extends AbstractKeycloakConfig {

            @Value("${keycloak.realm-name}")
            public String realmName;

            @Value("${keycloak.base-url}")
            public String baseUrl;

            @Value("${keycloak.relative-path}")
            public String relativePath;

            @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
            public String clientId;

            @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri}")
            public String redirectUri;

            @Value("${keycloak.logout.redirect.uri}")
            public String logoutRedirectUri;

            @Value("${keycloak.response.type}")
            public String responseType;
            
            @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
            public String clientSecret;

            @Override
            @Bean
            @ConditionalOnMissingBean
            public KeycloakClient keycloakClient() {
                log.info("핵심 Bean을 등록합니다: [KeycloakClient]");
                ClientConfiguration clientConfiguration = ClientConfiguration.builder()
                    .baseUrl(baseUrl)
                    .realmName(realmName)
                    .relativePath(relativePath)
                    .clientId(clientId)
                    .redirectUri(redirectUri)
                    .logoutRedirectUri(logoutRedirectUri)
                    .responseType(responseType)
                    .clientSecret(clientSecret)
                    .build();

                return new KeycloakClient(clientConfiguration);
            }
        }
    }

    /**
     * 인증 처리 (Authentication) 관련 Bean 설정
     */
    @Configuration(proxyBeanMethods = false)
    @Slf4j
    protected static class KeycloakAuthenticationConfiguration {

        @Bean
        @ConditionalOnMissingBean(AuthenticationManager.class)
        public AuthenticationManager authenticationManager(
            JwtDecoder jwtDecoder,
            KeycloakClient keycloakClient,
            ClientRegistrationRepository clientRegistrationRepository) {
            log.info("핵심 Bean을 등록합니다: [AuthenticationManager] (Provider: KeycloakAuthenticationProvider)");
            KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider(
                jwtDecoder,
                keycloakClient,
                clientRegistrationRepository
            );
            return new ProviderManager(provider);
        }

        @Bean
        @ConditionalOnMissingBean
        public KeycloakAuthenticationFilter keycloakAuthenticationFilter(
            AuthenticationManager authenticationManager,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            ClientRegistrationRepository clientRegistrationRepository,
            ObjectMapper objectMapper) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAuthenticationFilter]");
            return new KeycloakAuthenticationFilter(authenticationManager, authorizedClientRepository, clientRegistrationRepository, objectMapper);
        }
    }

    /**
     * 웹 보안 (Web Security) 관련 Bean 설정
     */
    @Configuration(proxyBeanMethods = false)
    @Slf4j
    protected static class KeycloakWebSecurityConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint(ObjectMapper objectMapper) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAuthenticationEntryPoint]");
            return new KeycloakAuthenticationEntryPoint(objectMapper);
        }

        @Bean
        @ConditionalOnMissingBean
        public KeycloakAccessDeniedHandler keycloakAccessDeniedHandler(ObjectMapper objectMapper) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAccessDeniedHandler]");
            return new KeycloakAccessDeniedHandler(objectMapper);
        }

        @Bean
        @ConditionalOnMissingBean
        public OidcLoginSuccessHandler oidcLoginSuccessHandler(OAuth2AuthorizedClientRepository authorizedClientRepository) {
            log.debug("지원 Bean을 등록합니다: [OidcLoginSuccessHandler]");
            return new OidcLoginSuccessHandler(authorizedClientRepository);
        }

        @Bean
        @ConditionalOnMissingBean(SecurityFilterChain.class)
        public SecurityFilterChain keycloakSecurityFilterChain(
            HttpSecurity http,
            OidcLoginSuccessHandler oidcLoginSuccessHandler,
            OAuth2AuthorizedClientRepository authorizedClientRepository
        ) throws Exception {
            log.info("핵심 Bean을 등록합니다: [SecurityFilterChain]");

            // 1. 핵심 인증/인가 로직을 Configurer에 모두 위임하여 적용
            http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());

            // 2. OIDC 로그인 관련 설정만 AutoConfiguration에서 담당
            http.oauth2Login(login -> login
                .successHandler(oidcLoginSuccessHandler)
                .authorizedClientRepository(authorizedClientRepository)
            );

            return http.build();
        }
    }
}
