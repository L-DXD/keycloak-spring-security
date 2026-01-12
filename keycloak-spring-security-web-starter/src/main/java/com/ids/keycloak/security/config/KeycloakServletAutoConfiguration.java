package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakLogoutHandler;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.session.KeycloakSessionManager;
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
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Keycloak Spring Security의 Servlet 환경 자동 설정을 담당하는 진입점입니다.
 * 역할별로 분리된 내부 설정 클래들을 Import 합니다.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties({CookieProperties.class, KeycloakSecurityProperties.class})
@Import({
    // 세션 관련 설정을 가장 먼저 임포트하여 Bean 생성 순서를 보장합니다.
    KeycloakServletAutoConfiguration.SessionConfiguration.class,
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
     * 세션 관리 관련 Bean 설정
     */
    @Configuration(proxyBeanMethods = false)
    @EnableSpringHttpSession
    @Slf4j
    protected static class SessionConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public KeycloakSessionManager keycloakSessionManager() {
            log.debug("지원 Bean을 등록합니다: [KeycloakSessionManager]");
            return new KeycloakSessionManager();
        }

        /**
         * Principal Name으로 세션을 검색할 수 있는 인-메모리 세션 저장소 Bean.
         * 사용자가 다른 구현(ex: Redis)을 원할 경우를 대비하여 @ConditionalOnMissingBean 적용.
         * 백채널 로그아웃 기능을 위해 FindByIndexNameSessionRepository 인터페이스를 구현합니다.
         */
        @Bean
        @ConditionalOnMissingBean(FindByIndexNameSessionRepository.class)
        public FindByIndexNameSessionRepository<MapSession> sessionRepository() {
            log.info("IndexedMapSessionRepository (In-Memory with Principal Name Index) 생성");
            return new IndexedMapSessionRepository(new ConcurrentHashMap<>());
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
        public OidcLoginSuccessHandler oidcLoginSuccessHandler(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            KeycloakSessionManager sessionManager
        ) {
            log.debug("지원 Bean을 등록합니다: [OidcLoginSuccessHandler]");
            return new OidcLoginSuccessHandler(authorizedClientRepository, sessionManager);
        }

        @Bean
        @ConditionalOnMissingBean
        public KeycloakLogoutHandler keycloakLogoutHandler(
            KeycloakClient keycloakClient,
            KeycloakSessionManager sessionManager
        ) {
            log.debug("지원 Bean을 등록합니다: [KeycloakLogoutHandler]");
            return new KeycloakLogoutHandler(keycloakClient, sessionManager);
        }

        @Bean
        @ConditionalOnMissingBean
        public OidcClientInitiatedLogoutSuccessHandler oidcClientInitiatedLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
            log.debug("지원 Bean을 등록합니다: [OidcClientInitiatedLogoutSuccessHandler]");
            OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            handler.setPostLogoutRedirectUri("{baseUrl}");
            return handler;
        }

        @Bean
        @ConditionalOnMissingBean(SecurityFilterChain.class)
        public SecurityFilterChain keycloakSecurityFilterChain(
            HttpSecurity http,
            KeycloakSecurityProperties securityProperties
        ) throws Exception {
            log.info("핵심 Bean을 등록합니다: [SecurityFilterChain]");

            // 1. Keycloak 핵심 설정을 Configurer에서 적용
            // (인증 필터, 프로바이더, 로그인, 로그아웃, 세션, CSRF 등)
            http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());

            // 2. 인가 설정 - permitAllPaths는 인증 없이 접근, 나머지는 인증 필요
            http.authorizeHttpRequests(authorize -> {
                // permit-all-paths 설정된 경로들은 인증 없이 접근 허용
                if (!securityProperties.getPermitAllPaths().isEmpty()) {
                    String[] permitAllPaths = securityProperties.getPermitAllPaths().toArray(new String[0]);
                    authorize.requestMatchers(permitAllPaths).permitAll();
                    log.info("인증 제외 경로 설정: {}", securityProperties.getPermitAllPaths());
                }
                // 나머지 모든 요청은 인증 필요
                authorize.anyRequest().authenticated();
            });

            return http.build();
        }
    }
}