package com.ids.keycloak.security.autoconfigure;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

import com.ids.keycloak.security.KeycloakSecurityVersion;
import com.ids.keycloak.security.authentication.DefaultKeycloakPrincipalConverter;
import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.config.KeycloakProvider;
import com.ids.keycloak.security.config.KeycloakSecurityConfigurationException;
import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.config.SessionStoreType;
import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.event.CompositeKeycloakSessionEventPublisher;
import com.ids.keycloak.security.event.KeycloakSessionAuditLogger;
import com.ids.keycloak.security.event.KeycloakSessionEventListener;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.JdbcKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionCleaner;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.token.DefaultKeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.JwkSetFetcher;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.KeycloakJwkSource;
import com.ids.keycloak.security.token.NimbusJwkSetFetcher;
import com.ids.keycloak.security.web.config.KeycloakHttpConfigurer;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;
import com.ids.keycloak.security.web.cors.KeycloakCors;
import com.ids.keycloak.security.web.csrf.SignedDoubleSubmitCsrfTokenRepository;
import com.ids.keycloak.security.web.error.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.web.error.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;
import com.ids.keycloak.security.web.login.DefaultLoginReturnPathResolver;
import com.ids.keycloak.security.web.login.KeycloakAuthorizationRequestRepository;
import com.ids.keycloak.security.web.login.KeycloakLoginFailureHandler;
import com.ids.keycloak.security.web.login.KeycloakLoginSuccessHandler;
import com.ids.keycloak.security.web.login.LoginReturnPathResolver;
import com.ids.keycloak.security.web.logging.WebMdcContextAccessor;
import com.ids.keycloak.security.web.logout.KeycloakBackChannelLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLogoutSuccessHandler;
import com.ids.keycloak.security.web.logout.KeycloakRefreshTokenRevoker;
import com.ids.keycloak.security.web.refresh.DefaultKeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshService;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;

/**
 * Servlet 앱 자동 설정 (v3). 모든 빈은 {@code @ConditionalOnMissingBean}이라 같은 빈을 올리면 그것을 쓴다.
 * <p>
 * 지금 올리는 것: 설정 검사·기동 로그(#79), 액세스 토큰 로컬 검증(#80), 세션 저장소·암호·정리 작업·세션 이벤트(#81), 쿠키(#82),
 * 로그인·오류 응답·기본 보안 체인(#83). 요청 인증·갱신·CSRF·로그아웃은 이슈마다 여기에 더한다.
 * Boot의 기본 보안 체인보다 먼저 돈다.
 */
@AutoConfiguration(
    after = OAuth2ClientAutoConfiguration.class,
    beforeName = {
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration"
    })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(ClientRegistrationRepository.class)
@ConditionalOnBooleanProperty(name = KeycloakSecuritySettings.PREFIX + ".enabled", matchIfMissing = true)
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
public class KeycloakSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(KeycloakSecurityAutoConfiguration.class);

    /**
     * 설정을 검사한다. 잘못되면 기동하지 않는다 (CONF-02~04). 지연 초기화를 켜도 기동 때 검사한다.
     */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakSecuritySettings keycloakSecuritySettings(KeycloakSecurityProperties properties,
                                                             ObjectProvider<ClientRegistrationRepository> registrations) {
        String registrationId = properties.getRegistrationId();
        ClientRegistration registration = findRegistration(registrations.getIfAvailable(), registrationId);
        KeycloakSecuritySettings.Builder builder = properties.toSettingsBuilder(registration == null ? null : registration.getClientId());
        String registrationProperty = "spring.security.oauth2.client.registration." + registrationId;
        if (registration == null) {
            builder.problem(registrationProperty, "OAuth2 Client 등록이 없습니다 (client-id, client-secret, provider.issuer-uri)");
        } else {
            if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
                builder.problem(registrationProperty + ".authorization-grant-type", "authorization_code여야 합니다");
            }
            if (ClientAuthenticationMethod.NONE.equals(registration.getClientAuthenticationMethod())) {
                builder.problem(registrationProperty + ".client-secret", "비공개 client여야 합니다 (client-secret이 필요합니다)");
            }
            String providerProperty = "spring.security.oauth2.client.provider." + registrationId;
            ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
            if (isBlank(provider.getIssuerUri())) {
                builder.problem(providerProperty + ".issuer-uri", "필수입니다 (토큰 iss 검사). 예: https://sso.example.com/realms/demo");
            }
            if (isBlank(provider.getJwkSetUri())) {
                builder.problem(providerProperty + ".jwk-set-uri", "서명 키 주소가 없습니다 (issuer-uri를 주면 저절로 채워집니다)");
            }
            if (isBlank(provider.getTokenUri())) {
                builder.problem(providerProperty + ".token-uri", "토큰 주소가 없습니다 (issuer-uri를 주면 저절로 채워집니다)");
            }
        }
        KeycloakSecuritySettings settings = builder.build();
        logStartup(settings, registration);
        return settings;
    }

    /** 붙을 Keycloak realm과 client. 설정 검사를 마친 뒤 OAuth2 등록에서 만든다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakProvider keycloakProvider(KeycloakSecuritySettings settings, ClientRegistrationRepository registrations) {
        ClientRegistration registration = findRegistration(registrations, settings.registrationId());
        if (registration == null) {
            throw new IllegalStateException("OAuth2 Client 등록이 없습니다: " + settings.registrationId());
        }
        ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
        Object endSession = provider.getConfigurationMetadata().get("end_session_endpoint");
        return new KeycloakProvider(registration.getRegistrationId(), registration.getClientId(), provider.getIssuerUri(),
            URI.create(provider.getJwkSetUri()), URI.create(provider.getTokenUri()),
            endSession == null ? null : URI.create(endSession.toString()));
    }

    /** JWKS 받기. 프록시·타임아웃을 바꾸려면 이 빈을 바꾼다. */
    @Bean
    @ConditionalOnMissingBean
    public JwkSetFetcher keycloakJwkSetFetcher(KeycloakProvider provider) {
        return new NimbusJwkSetFetcher(provider.jwkSetUri());
    }

    /** 액세스 토큰 로컬 검증 (JWT-01~08). Keycloak을 부르지 않는다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakAccessTokenValidator keycloakAccessTokenValidator(KeycloakSecuritySettings settings, KeycloakProvider provider,
                                                                     JwkSetFetcher jwkSetFetcher,
                                                                     @Qualifier("keycloakSecurityClock") Clock clock) {
        return new DefaultKeycloakAccessTokenValidator(new KeycloakJwkSource(jwkSetFetcher, clock), provider.issuer(),
            provider.clientId(), settings.requiredAudience(), settings.clockSkew(), clock);
    }

    /** 리프레시 토큰 암호 (AES-256-GCM, 키 id로 교체). KMS·HSM을 쓰려면 이 빈을 바꾼다. */
    @Bean
    @ConditionalOnMissingBean
    public TokenCipher keycloakTokenCipher(KeycloakSecuritySettings settings) {
        return new AesGcmTokenCipher(settings.keyRing());
    }

    /**
     * 세션 행 저장소. {@code session.store=jdbc}(기본)면 앱의 DataSource를 쓰고, 기동 때 테이블과 열이 있는지 본다.
     * Flyway 등 DB 초기화가 끝난 뒤에 만든다. 다른 DB·테이블 구조는 이 빈을 바꾼다.
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    public KeycloakSessionStore keycloakSessionStore(KeycloakSecuritySettings settings, ObjectProvider<DataSource> dataSources) {
        if (settings.sessionStore() == SessionStoreType.MEMORY) {
            return new InMemoryKeycloakSessionStore();
        }
        DataSource dataSource = dataSources.getIfUnique();
        if (dataSource == null) {
            throw configurationProblem(KeycloakSecuritySettings.PREFIX + ".session.store",
                "jdbc인데 쓸 DataSource가 없습니다 (없거나 여러 개인데 @Primary가 없음). spring-boot-starter-jdbc와 spring.datasource.*를 넣거나, "
                    + "개발·테스트라면 memory를 쓰세요");
        }
        JdbcKeycloakSessionStore store = new JdbcKeycloakSessionStore(dataSource, settings.sessionTableName());
        try {
            store.verifySchema();
        } catch (IllegalStateException e) {
            throw configurationProblem(KeycloakSecuritySettings.PREFIX + ".session.table-name", e.getMessage());
        }
        return store;
    }

    /** 쿠키 쓰기 ({@code __Host-{앱 이름}_*}, Secure, HttpOnly, SameSite=Lax, Path=/). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakCookieWriter keycloakCookieWriter(KeycloakSecuritySettings settings) {
        return new DefaultKeycloakCookieWriter(settings.cookieAppName());
    }

    /** CSRF 토큰 서명 (sid에 묶인 double-submit 토큰). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakCsrfTokenSigner keycloakCsrfTokenSigner(KeycloakSecuritySettings settings) {
        return new KeycloakCsrfTokenSigner(settings.keyRing());
    }

    /** 401·403·503 JSON. 앱 오류 형식을 쓰려면 이 빈을 바꾼다. */
    /** CSRF 토큰 저장소 (sid 서명 double-submit, csrf 쿠키). */
    @Bean
    @ConditionalOnMissingBean(CsrfTokenRepository.class)
    public SignedDoubleSubmitCsrfTokenRepository keycloakCsrfTokenRepository(KeycloakCsrfTokenSigner signer, KeycloakCookieWriter cookies,
                                                                            KeycloakSecuritySettings settings) {
        return new SignedDoubleSubmitCsrfTokenRepository(signer, cookies, settings.absoluteTimeout());
    }

    /**
     * CORS: 화면 origin 하나, 쿠키 허용. 이름으로만 비켜 선다(Spring MVC가 올리는 다른 {@link CorsConfigurationSource}와 섞이지 않게).
     * Origin 확인도 이 허용 목록을 쓴다.
     */
    @Bean(name = KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN)
    @ConditionalOnMissingBean(name = KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN)
    public CorsConfigurationSource keycloakCorsConfigurationSource(KeycloakSecuritySettings settings) {
        return KeycloakCors.source(KeycloakCors.configuration(settings.frontendOrigin(), settings.backgroundHeader()));
    }

    @Bean
    @ConditionalOnMissingBean
    public KeycloakErrorResponseWriter keycloakErrorResponseWriter(KeycloakSecuritySettings settings) {
        return new KeycloakErrorResponseWriter(settings.registrationId());
    }

    /** 로그인이 필요하면 401 JSON (로그인 주소 포함). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakAuthenticationEntryPoint keycloakAuthenticationEntryPoint(KeycloakErrorResponseWriter writer) {
        return new KeycloakAuthenticationEntryPoint(writer);
    }

    /** 권한이 없으면 403 JSON. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakAccessDeniedHandler keycloakAccessDeniedHandler(KeycloakErrorResponseWriter writer) {
        return new KeycloakAccessDeniedHandler(writer);
    }

    /** 로그인 뒤 돌아갈 경로 ({@code ?return=}, 상대 경로만). */
    @Bean
    @ConditionalOnMissingBean
    public LoginReturnPathResolver keycloakLoginReturnPathResolver() {
        return new DefaultLoginReturnPathResolver();
    }

    /** 로그인 임시 정보를 암호화 쿠키({@code _login}, 5분)에 둔다. HttpSession을 쓰지 않는다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakAuthorizationRequestRepository keycloakAuthorizationRequestRepository(KeycloakCookieWriter cookies,
                                                                                         KeycloakSecuritySettings settings,
                                                                                         LoginReturnPathResolver returnPaths,
                                                                                         @Qualifier("keycloakSecurityClock") Clock clock) {
        return new KeycloakAuthorizationRequestRepository(cookies, settings.keyRing(), returnPaths, clock);
    }

    /** 로그인 실패: 화면 주소로 {@code ?login_error=}. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakLoginFailureHandler keycloakLoginFailureHandler(KeycloakSecuritySettings settings, KeycloakCookieWriter cookies) {
        return new KeycloakLoginFailureHandler(settings.frontendBaseUrl(), cookies);
    }

    /** 로그인 성공: 세션 행과 sid·at·csrf 쿠키를 만들고 화면으로. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakLoginSuccessHandler keycloakLoginSuccessHandler(KeycloakAccessTokenValidator validator, KeycloakSessionStore store,
                                                                   TokenCipher cipher, KeycloakCsrfTokenSigner csrf,
                                                                   KeycloakCookieWriter cookies, KeycloakSessionEventPublisher events,
                                                                   KeycloakLoginFailureHandler failureHandler,
                                                                   @Qualifier("keycloakSecurityClock") Clock clock,
                                                                   KeycloakSecuritySettings settings) {
        return new KeycloakLoginSuccessHandler(validator, store, cipher, csrf, cookies, events, failureHandler, clock,
            settings.absoluteTimeout(), settings.frontendBaseUrl());
    }

    /** 기본 감사 로그. {@link KeycloakSessionEventListener}를 올리면 그것으로 바뀐다. */
    @Bean
    @ConditionalOnMissingBean(KeycloakSessionEventListener.class)
    public KeycloakSessionAuditLogger keycloakSessionAuditLogger() {
        return new KeycloakSessionAuditLogger();
    }

    /** 세션 이벤트를 {@link KeycloakSessionEventListener} 빈들과 Spring 이벤트({@code @EventListener})로 보낸다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakSessionEventPublisher keycloakSessionEventPublisher(ObjectProvider<KeycloakSessionEventListener> listeners,
                                                                       ApplicationEventPublisher applicationEvents) {
        List<KeycloakSessionEventListener> all = new ArrayList<>(listeners.orderedStream().toList());
        all.add(applicationEvents::publishEvent);
        return new CompositeKeycloakSessionEventPublisher(all);
    }

    /** 끝난 세션 행 정리 ({@code session.cleanup-interval}마다). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakSessionCleaner keycloakSessionCleaner(KeycloakSessionStore store, KeycloakSessionEventPublisher events,
                                                         @Qualifier("keycloakSecurityClock") Clock clock, KeycloakSecuritySettings settings) {
        return new KeycloakSessionCleaner(store, events, clock, settings.cleanupInterval());
    }

    /** 검증을 통과한 액세스 토큰 → 인증 (요청 인증). 기본은 권한 없음. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakPrincipalConverter keycloakPrincipalConverter() {
        return new DefaultKeycloakPrincipalConverter();
    }

    /** 로컬 로그아웃 (행·쿠키 삭제, ENDED 이벤트). 토큰 검증 실패·갱신 실패에 쓴다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakLocalLogoutHandler keycloakLocalLogoutHandler(KeycloakSessionStore store, KeycloakCookieWriter cookies,
                                                                 KeycloakSessionEventPublisher events,
                                                                 @Qualifier("keycloakSecurityClock") Clock clock,
                                                                 KeycloakRefreshTokenRevoker revoker) {
        return new KeycloakLocalLogoutHandler(store, cookies, events, clock, revoker);
    }

    /** 로컬 로그아웃 때 리프레시 토큰 폐기 (옵션 logout.revoke-refresh-token-on-local-logout, 기본 끔). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakRefreshTokenRevoker keycloakRefreshTokenRevoker(KeycloakSecuritySettings settings, TokenCipher cipher,
                                                                   KeycloakTokenClient tokenClient) {
        return new KeycloakRefreshTokenRevoker(settings.revokeRefreshTokenOnLocalLogout(), cipher, tokenClient);
    }

    /** POST /logout: 세션 행·쿠키를 지우고 Keycloak 로그아웃을 서버끼리 부른다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakLogoutHandler keycloakLogoutHandler(KeycloakSessionStore store, TokenCipher cipher, KeycloakTokenClient tokenClient,
                                                       KeycloakCookieWriter cookies, KeycloakSessionEventPublisher events,
                                                       @Qualifier("keycloakSecurityClock") Clock clock) {
        return new KeycloakLogoutHandler(store, cipher, tokenClient, cookies, events, clock);
    }

    /** back-channel 로그아웃: 검증된 logout_token의 sid로 세션 행을 지운다. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakBackChannelLogoutHandler keycloakBackChannelLogoutHandler(KeycloakSessionStore store, KeycloakSessionEventPublisher events,
                                                                             @Qualifier("keycloakSecurityClock") Clock clock) {
        return new KeycloakBackChannelLogoutHandler(store, events, clock);
    }

    /** 로그아웃 뒤: 화면 로그아웃 주소, Keycloak 로그아웃을 못 했으면 OIDC 로그아웃 주소로 302. */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakLogoutSuccessHandler keycloakLogoutSuccessHandler(KeycloakSecuritySettings settings, KeycloakProvider provider) {
        return new KeycloakLogoutSuccessHandler(settings.frontendLogoutUrl(), provider.endSessionEndpoint(), provider.clientId());
    }

    /** Keycloak 토큰 주소 호출 (갱신·로그아웃·폐기). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakTokenClient keycloakTokenClient(ClientRegistrationRepository registrations, KeycloakSecuritySettings settings) {
        return new DefaultKeycloakTokenClient(registrations.findByRegistrationId(settings.registrationId()));
    }

    /** 갱신 (세션 행 잠금 → Keycloak 갱신, 동시 요청은 한 번만). */
    @Bean
    @ConditionalOnMissingBean
    public KeycloakRefreshService keycloakRefreshService(KeycloakSessionStore store, TokenCipher cipher, KeycloakTokenClient tokenClient,
                                                         KeycloakAccessTokenValidator validator, KeycloakSessionEventPublisher events,
                                                         @Qualifier("keycloakSecurityClock") Clock clock, KeycloakSecuritySettings settings,
                                                         KeycloakRefreshTokenRevoker revoker) {
        return new KeycloakRefreshService(store, cipher, tokenClient, validator, events, clock, settings.refreshReuseWindow(), revoker);
    }

    /** MDC 접근자 (v2와 같은 키). 사내 로깅 표준에 맞추려면 이 타입의 빈을 올린다. */
    @Bean
    @ConditionalOnMissingBean(LoggingContextAccessor.class)
    public WebMdcContextAccessor keycloakLoggingContextAccessor() {
        return new WebMdcContextAccessor();
    }

    /** 로그에 넣기 전 값 가리기 (JWT·Bearer·OAuth2 파라미터·주민번호·카드·이메일·전화). 가리지 않으려면 {@code NoOpLoggingValueSanitizer} 빈. */
    @Bean
    @ConditionalOnMissingBean
    public LoggingValueSanitizer keycloakLoggingValueSanitizer() {
        return new DefaultPiiMaskingSanitizer();
    }

    /** 설정 검사, 세션 테이블 검사, 정리 작업을 지연 초기화에서 뺀다 (잘못되면 첫 요청이 아니라 기동 때 알도록). */
    @Bean
    @ConditionalOnMissingBean(name = "keycloakSecurityEagerInit")
    public static LazyInitializationExcludeFilter keycloakSecurityEagerInit() {
        return LazyInitializationExcludeFilter.forBeanTypes(KeycloakSecuritySettings.class, KeycloakSessionStore.class,
            KeycloakSessionCleaner.class);
    }

    /** 라이브러리가 쓰는 시계. 테스트에서 바꿔 끼운다 (절대 상한·만료 시나리오). */
    @Bean(name = "keycloakSecurityClock")
    @ConditionalOnMissingBean(name = "keycloakSecurityClock")
    public Clock keycloakSecurityClock() {
        return Clock.systemUTC();
    }

    /**
     * 기본 보안 체인: {@code permit-all-paths}와 {@code /error}는 허용, 나머지는 로그인 필요, Keycloak 로그인.
     * 앱이 {@link SecurityFilterChain}을 올리면 빠진다. 그때는 앱 체인에 {@link KeycloakHttpConfigurer}를 붙인다.
     * Boot의 보안 자동 설정을 빼도 돌도록 {@code @EnableWebSecurity}를 같이 둔다.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @EnableWebSecurity
    static class KeycloakSecurityFilterChainConfiguration {

        @Bean(name = "keycloakSecurityFilterChain")
        SecurityFilterChain keycloakSecurityFilterChain(HttpSecurity http, KeycloakSecuritySettings settings) throws Exception {
            http.authorizeHttpRequests(a -> {
                a.requestMatchers("/error").permitAll();
                for (String path : settings.permitAllPaths()) {
                    a.requestMatchers(path).permitAll();
                }
                a.anyRequest().authenticated();
            }).with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());
            return http.build();
        }
    }

    private static ClientRegistration findRegistration(ClientRegistrationRepository repository, String registrationId) {
        if (repository == null || registrationId == null || registrationId.isBlank()) {
            return null;
        }
        return repository.findByRegistrationId(registrationId);
    }

    private static KeycloakSecurityConfigurationException configurationProblem(String property, String message) {
        return new KeycloakSecurityConfigurationException(List.of(new KeycloakSecurityConfigurationException.Problem(property, message)));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** CONF-01·05: 기동 로그. 비밀값(키, client secret)은 찍지 않는다. */
    private static void logStartup(KeycloakSecuritySettings settings, ClientRegistration registration) {
        String store = settings.sessionStore().name().toLowerCase(Locale.ROOT)
            + (settings.sessionStore() == SessionStoreType.JDBC ? "(" + settings.sessionTableName() + ")" : "");
        log.info("[KSS] keycloak-spring-security v3 ({}) 켜짐: 세션 저장소={}, 앱 이름={}, 화면 주소={}, 클라이언트={}({}), 활성 키={}",
            KeycloakSecurityVersion.current(), store, settings.cookieAppName(), settings.frontendBaseUrl(),
            settings.registrationId(), registration.getClientId(), settings.keyRing().activeKeyId());
        if (settings.sessionStore() == SessionStoreType.MEMORY) {
            log.warn("[KSS] 세션 저장소가 memory입니다. 서버를 여러 대 띄우면 로그인이 서로 보이지 않고, 재시작하면 모두 로그아웃됩니다. "
                + "개발·테스트에만 쓰고 운영에서는 keycloak.security.session.store=jdbc를 쓰세요.");
        }
        if (settings.trustedProxyCount() < 0) {
            log.warn("[KSS] keycloak.security.trusted-proxy-count=-1: 로그의 clientIp에 X-Forwarded-For 첫 값(클라이언트가 쓸 수 있음)을 씁니다. "
                + "앞에 있는 프록시 수를 넣으세요.");
        }
    }
}
