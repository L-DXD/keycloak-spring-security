package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.BasicAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakLogoutHandler;
import com.ids.keycloak.security.authentication.KeycloakOpaqueTokenIntrospector;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.controller.KeycloakTokenController;
import com.ids.keycloak.security.exception.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.manager.KeycloakAuthorizationManager;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.sd.KeycloakClient.config.AbstractKeycloakConfig;
import com.sd.KeycloakClient.config.ClientConfiguration;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.DispatcherType;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

/**
 * Keycloak Spring Security의 Servlet 환경 자동 설정을 담당하는 진입점입니다.
 * 역할별로 분리된 내부 설정 클래들을 Import 합니다.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties({KeycloakSecurityProperties.class})
@AutoConfigureAfter(name = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@Import({
    // 세션 관련 설정 (Memory/Redis는 별도 Configuration 클래스로 분리)
    KeycloakServletAutoConfiguration.SessionConfiguration.class,
    MemorySessionConfiguration.class,
    RedisSessionConfiguration.class,
    KeycloakServletAutoConfiguration.KeycloakInfrastructureConfiguration.class,
    KeycloakServletAutoConfiguration.KeycloakAuthenticationConfiguration.class,
    KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration.class,
    KeycloakServletAutoConfiguration.BearerTokenConfiguration.class
})
@EnableMethodSecurity
@Slf4j
public class KeycloakServletAutoConfiguration {
    public KeycloakServletAutoConfiguration() {
        log.info("Keycloak Spring Security: Servlet 환경 자동 설정이 활성화되었습니다.");
    }

    @Configuration(proxyBeanMethods = false)
    @RequiredArgsConstructor
    static class CookieUtilInitializer {
        private final KeycloakSecurityProperties securityProperties;

        @PostConstruct
        public void init() {
            log.debug("CookieUtil에 CookieProperties를 주입합니다.");
            CookieUtil.setProperties(securityProperties.getCookie());
        }
    }

    /**
     * 세션 관리 관련 공통 Bean 설정.
     * <p>
     * 세션 저장소(Memory/Redis)는 별도 Configuration 클래스로 분리되었습니다.
     * - MemorySessionConfiguration: keycloak.session.store-type=memory (기본값)
     * - RedisSessionConfiguration: keycloak.session.store-type=redis
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @Slf4j
    protected static class SessionConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public KeycloakSessionManager keycloakSessionManager() {
            log.debug("지원 Bean을 등록합니다: [KeycloakSessionManager]");
            return new KeycloakSessionManager();
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
            KeycloakClient keycloakClient,
            KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig,
            KeycloakSecurityProperties securityProperties
        ) {
            List<AuthenticationProvider> providers = new ArrayList<>();

            KeycloakAuthenticationProvider oidcProvider = new KeycloakAuthenticationProvider(keycloakClient, keycloakConfig.getClientId());
            providers.add(oidcProvider);

            if (securityProperties.getBasicAuth().isEnabled()) {
                String tokenEndpoint = keycloakConfig.getBaseUrl()
                    + keycloakConfig.getRelativePath()
                    + "/realms/" + keycloakConfig.getRealmName()
                    + "/protocol/openid-connect/token";
                BasicAuthenticationProvider basicProvider = new BasicAuthenticationProvider(
                    tokenEndpoint,
                    keycloakConfig.getClientId(),
                    keycloakConfig.getClientSecret(),
                    oidcProvider
                );
                providers.add(basicProvider);
                log.info("핵심 Bean을 등록합니다: [AuthenticationManager] (Providers: KeycloakAuthenticationProvider, BasicAuthenticationProvider)");
            } else {
                log.info("핵심 Bean을 등록합니다: [AuthenticationManager] (Provider: KeycloakAuthenticationProvider)");
            }

            return new ProviderManager(providers);
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
        public KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint(
            ObjectMapper objectMapper,
            KeycloakSecurityProperties securityProperties,
            KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig
        ) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAuthenticationEntryPoint]");
            return new KeycloakAuthenticationEntryPoint(
                objectMapper,
                securityProperties.getError(),
                securityProperties.getBasicAuth().isEnabled(),
                keycloakConfig.getRealmName()
            );
        }

        @Bean
        @ConditionalOnMissingBean
        public KeycloakAccessDeniedHandler keycloakAccessDeniedHandler(
            ObjectMapper objectMapper,
            KeycloakSecurityProperties securityProperties
        ) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAccessDeniedHandler]");
            return new KeycloakAccessDeniedHandler(objectMapper, securityProperties.getError());
        }

        @Bean
        @ConditionalOnMissingBean
        public OidcLoginSuccessHandler oidcLoginSuccessHandler(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            KeycloakSessionManager sessionManager,
            KeycloakSecurityProperties securityProperties
        ) {
            log.debug("지원 Bean을 등록합니다: [OidcLoginSuccessHandler]");
            String defaultSuccessUrl = securityProperties.getAuthentication().getDefaultSuccessUrl();
            return new OidcLoginSuccessHandler(authorizedClientRepository, sessionManager, defaultSuccessUrl);
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
        @ConditionalOnMissingBean
        public KeycloakAuthorizationManager keycloakAuthorizationManager(KeycloakClient keycloakClient) {
            log.debug("지원 Bean을 등록합니다: [KeycloakAuthorizationManager]");
            return new KeycloakAuthorizationManager(keycloakClient);
        }

        @Bean
        @ConditionalOnMissingBean(SecurityFilterChain.class)
        public SecurityFilterChain keycloakSecurityFilterChain(
            HttpSecurity http,
            KeycloakSecurityProperties securityProperties,
            ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessionRepositoryProvider,
            KeycloakAuthorizationManager keycloakAuthorizationManager
        ) throws Exception {
            log.info("핵심 Bean을 등록합니다: [SecurityFilterChain]");

            // 1. Keycloak 핵심 설정을 Configurer에서 적용
            // (인증 필터, 프로바이더, 로그인, 로그아웃, 세션, CSRF 등)
            // 세션 리포지토리를 명시적으로 주입하여 빈 생성 순서 보장
            http.with(KeycloakHttpConfigurer.keycloak()
                    .sessionRepository(sessionRepositoryProvider.getIfAvailable()),
                Customizer.withDefaults());

            // 2. 인가 설정
            http.authorizeHttpRequests(authorize -> {
                // 에러 페이지는 인증 없이 접근 허용 (정적 리소스 누락 시 로그인 리디렉션 방지)
                authorize.requestMatchers("/error").permitAll();

                // 비동기(ASYNC) 및 에러(ERROR) 디스패치는 인증 없이 통과 허용
                // StreamingResponseBody 등 비동기 처리 시 SecurityContext가 전파되지 않는 문제 해결
                // (이미 REQUEST 단계에서 인증/인가가 완료되었으므로 안전함)
                authorize.dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll();

                // Bearer Token 토큰 발급/갱신 엔드포인트는 미인증 허용
                if (securityProperties.getBearerToken().isEnabled()) {
                    String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
                    authorize.requestMatchers(prefix + "/token", prefix + "/refresh", prefix + "/logout").permitAll();
                    log.info("Bearer Token 엔드포인트 인증 제외: {}/token, {}/refresh, {}/logout", prefix, prefix, prefix);
                }

                // permit-all-paths 설정된 경로들은 인증 없이 접근 허용
                if (!securityProperties.getAuthentication().getPermitAllPaths().isEmpty()) {
                    String[] permitAllPaths = securityProperties.getAuthentication().getPermitAllPaths().toArray(new String[0]);
                    authorize.requestMatchers(permitAllPaths).permitAll();
                    log.info("인증 제외 경로 설정: {}", securityProperties.getAuthentication().getPermitAllPaths());
                }

                // 에러 페이지는 인증 없이 접근 허용 (정적 리소스 누락 시 로그인 리디렉션 방지)
                authorize.requestMatchers("/error").permitAll();

                // authorization-enabled 여부에 따라 인가 방식 결정
                if (securityProperties.getAuthorization().isEnabled()) {
                    log.info("Keycloak Authorization Services 활성화: 모든 요청에 대해 Keycloak 인가 검증");
                    authorize.anyRequest().access(keycloakAuthorizationManager);
                } else {
                    // 나머지 모든 요청은 인증만 필요
                    authorize.anyRequest().authenticated();
                }
            });

            return http.build();
        }
    }

    /**
     * Bearer Token 인증 관련 Bean 설정.
     * <p>
     * {@code keycloak.security.bearer-token.enabled=true}일 때만 활성화됩니다.
     * Keycloak Introspect API(RFC 7662) 기반 온라인 검증만 지원합니다.
     * </p>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = "keycloak.security.bearer-token.enabled", havingValue = "true")
    @Slf4j
    protected static class BearerTokenConfiguration {

        /**
         * Introspect 검증 방식 Bean 설정 (Keycloak Introspect API 온라인 검증)
         */
        @Bean
        @ConditionalOnMissingBean(OpaqueTokenIntrospector.class)
        public OpaqueTokenIntrospector keycloakOpaqueTokenIntrospector(
            KeycloakClient keycloakClient,
            KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig
        ) {
            log.info("Bearer Token Bean을 등록합니다: [OpaqueTokenIntrospector] (Keycloak Introspect)");
            return new KeycloakOpaqueTokenIntrospector(keycloakClient, keycloakConfig.getClientId());
        }

        /**
         * 토큰 발급 API Controller Bean
         */
        @Bean
        @ConditionalOnMissingBean(KeycloakTokenController.class)
        public KeycloakTokenController keycloakTokenController(
            KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig,
            KeycloakSecurityProperties securityProperties
        ) {
            String basePath = keycloakConfig.getBaseUrl()
                + keycloakConfig.getRelativePath()
                + "/realms/" + keycloakConfig.getRealmName()
                + "/protocol/openid-connect";

            String tokenEndpoint = basePath + "/token";
            String logoutEndpoint = basePath + "/logout";
            String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();

            log.info("Bearer Token Bean을 등록합니다: [KeycloakTokenController] (prefix: {})", prefix);

            return new KeycloakTokenController(
                tokenEndpoint, logoutEndpoint,
                keycloakConfig.getClientId(), keycloakConfig.getClientSecret(),
                prefix
            );
        }
    }
}