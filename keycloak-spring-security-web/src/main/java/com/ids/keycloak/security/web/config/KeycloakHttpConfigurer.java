package com.ids.keycloak.security.web.config;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import java.util.Objects;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.web.authentication.KeycloakAccessTokenFilter;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;
import com.ids.keycloak.security.web.csrf.KeycloakCsrfTokenEndpointFilter;
import com.ids.keycloak.security.web.csrf.KeycloakOriginFilter;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;
import com.ids.keycloak.security.web.error.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.web.error.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.web.login.KeycloakAuthorizationRequestRepository;
import com.ids.keycloak.security.web.login.KeycloakLoginAuthorizedClientRepository;
import com.ids.keycloak.security.web.login.KeycloakLoginFailureHandler;
import com.ids.keycloak.security.web.login.KeycloakLoginSuccessHandler;
import com.ids.keycloak.security.web.logging.MdcAuthenticationFilter;
import com.ids.keycloak.security.web.logging.MdcRequestFilter;
import com.ids.keycloak.security.web.logout.KeycloakBackChannelLogoutErrorFilter;
import com.ids.keycloak.security.web.logout.KeycloakBackChannelLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLogoutHandler;
import com.ids.keycloak.security.web.logout.KeycloakLogoutMethodFilter;
import com.ids.keycloak.security.web.logout.KeycloakLogoutSuccessHandler;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshService;

/**
 * 보안 체인에 Keycloak 로그인을 붙인다. 기본 체인({@code keycloakSecurityFilterChain})이 쓰고, 사용자 체인에도 붙일 수 있다.
 * <pre>
 * http.authorizeHttpRequests(a -&gt; a.anyRequest().authenticated())
 *     .with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());
 * </pre>
 * 하는 일:
 * <ul>
 *   <li>HttpSession을 만들지 않는다 (요청 캐시 없음, 보안 컨텍스트는 요청 안에서만)</li>
 *   <li>로그인: Spring {@code oauth2Login} + PKCE S256 + 로그인 임시 쿠키 + UserInfo 호출 없음 + 라이브러리 성공·실패 처리</li>
 *   <li>요청 인증: at 쿠키를 로컬 검증하고 만료면 갱신하는 {@link KeycloakAccessTokenFilter}를 Basic 인증 자리 앞에 넣는다</li>
 *   <li>CORS(체인 맨 앞, 빈 {@value #CORS_CONFIGURATION_SOURCE_BEAN}) → Origin 확인({@link KeycloakOriginFilter}) → CSRF(sid 서명
 *       double-submit, Xor 처리기) → {@code GET /api/csrf}({@link KeycloakCsrfTokenEndpointFilter}). back-channel 로그아웃과 OIDC 콜백은
 *       Origin·CSRF 확인에서 뺀다</li>
 *   <li>로그아웃: {@code POST /logout}(CSRF 필요)만. 세션 행·쿠키를 지우고 Keycloak 로그아웃을 서버끼리 부른 뒤 화면으로 302,
 *       Keycloak 로그아웃을 하지 못하면 OIDC 로그아웃 주소로 302. 다른 메서드는 405</li>
 *   <li>401·403은 JSON (로그인 화면으로 302하지 않는다)</li>
 *   <li>MDC: 요청 정보({@link MdcRequestFilter}, 체인 맨 앞)와 사용자 정보({@link MdcAuthenticationFilter}, 인가 앞). 키는 v2와 같다</li>
 *   <li>폼 로그인, Basic 인증을 끈다</li>
 * </ul>
 * 빈은 애플리케이션 컨텍스트에서 타입으로 찾는다. 스타터가 모두 올린다.
 * <p>
 * 부분마다 {@link Customizer}를 받아 라이브러리 설정 <b>뒤에</b> 부른다(같은 값을 주면 사용자 것이 이긴다).
 * <pre>
 * .with(KeycloakHttpConfigurer.keycloak()
 *         .csrf(c -&gt; c.ignoringRequestMatchers("/api/webhooks/**"))
 *         .logout(l -&gt; l.addLogoutHandler(appCacheEvictor)),
 *     Customizer.withDefaults())
 * </pre>
 * 쿠키는 체인 밖의 빈(로그인 성공·갱신·로그아웃 처리기)이 같이 쓰므로 {@code KeycloakCookieWriter} 빈으로 바꾼다.
 */
public class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

    /** CORS 설정 빈 이름. 이 이름으로 올린 {@link CorsConfigurationSource}를 쓴다 (MVC의 다른 CORS 빈과 섞이지 않게 이름으로 찾는다). */
    public static final String CORS_CONFIGURATION_SOURCE_BEAN = "keycloakCorsConfigurationSource";

    /** 로그아웃 주소. POST만 받는다(CSRF 필요). */
    public static final String LOGOUT_PATH = "/logout";

    /** back-channel 로그아웃 주소 (Spring 기본). Keycloak 클라이언트의 Backchannel logout URL에 {@code /logout/connect/back-channel/keycloak}처럼 넣는다. */
    public static final String BACK_CHANNEL_LOGOUT_PATH = "/logout/connect/back-channel/{registrationId}";

    private Customizer<OAuth2LoginConfigurer<HttpSecurity>> login = Customizer.withDefaults();
    private Customizer<CsrfConfigurer<HttpSecurity>> csrf = Customizer.withDefaults();
    private Customizer<CorsConfigurer<HttpSecurity>> cors = Customizer.withDefaults();
    private Customizer<LogoutConfigurer<HttpSecurity>> logout = Customizer.withDefaults();

    /** 새 설정기. */
    public static KeycloakHttpConfigurer keycloak() {
        return new KeycloakHttpConfigurer();
    }

    /** 로그인({@code oauth2Login})을 라이브러리 설정 뒤에 고친다. 권한 요청 저장소·처리기를 바꾸면 라이브러리 로그인 흐름이 빠진다. */
    public KeycloakHttpConfigurer login(Customizer<OAuth2LoginConfigurer<HttpSecurity>> customizer) {
        this.login = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    /** CSRF를 라이브러리 설정 뒤에 고친다. 예: 확인에서 뺄 주소 더하기. */
    public KeycloakHttpConfigurer csrf(Customizer<CsrfConfigurer<HttpSecurity>> customizer) {
        this.csrf = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    /** CORS를 라이브러리 설정 뒤에 고친다. 허용 목록은 이름 {@value #CORS_CONFIGURATION_SOURCE_BEAN} 빈으로 바꾼다(Origin 확인도 그 목록을 쓴다). */
    public KeycloakHttpConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.cors = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    /** 로그아웃({@code POST /logout})을 라이브러리 설정 뒤에 고친다. 예: 앱 캐시를 비우는 처리기 더하기. */
    public KeycloakHttpConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.logout = Objects.requireNonNull(customizer, "customizer");
        return this;
    }

    @Override
    public void init(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        if (context == null) {
            throw new IllegalStateException("KeycloakHttpConfigurer는 Spring 컨텍스트 안의 HttpSecurity에서만 쓸 수 있습니다");
        }

        // HttpSession을 쓰지 않는다. sessionCreationPolicy(STATELESS)는 쓰지 않는다: 이 init보다 먼저 도는 세션 관리 설정이
        // HttpSession 저장소를 이미 골라 두었는데, 정책을 바꾸면 SessionManagementFilter가 켜져 로그인한 요청마다 세션을 만든다(REQ-05).
        // STATELESS가 해 주는 두 가지(요청 안에서만 쓰는 보안 컨텍스트, 요청 캐시 없음)를 직접 넣는다.
        http.securityContext(c -> c.securityContextRepository(new RequestAttributeSecurityContextRepository()))
            .requestCache(r -> r.requestCache(new NullRequestCache()))
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(l -> {
                l.logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, LOGOUT_PATH))
                    .addLogoutHandler(context.getBean(KeycloakLogoutHandler.class))
                    .logoutSuccessHandler(context.getBean(KeycloakLogoutSuccessHandler.class));
                logout.customize(l);
            })
            .cors(c -> {
                c.configurationSource(corsConfigurationSource(context));
                cors.customize(c);
            })
            .csrf(c -> {
                c.csrfTokenRepository(context.getBean(CsrfTokenRepository.class))
                    .csrfTokenRequestHandler(csrfTokenRequestHandler())
                    // 로그인하면 로그인 처리기가 새 sid에 묶은 토큰을 쓴다. Spring의 "로그인 때 토큰 지우고 다시 만들기"는 쿠키를 두 번 쓰게 하므로 끈다
                    .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
                    .ignoringRequestMatchers(serverCallbacks());
                csrf.customize(c);
            })
            .exceptionHandling(e -> e
                .authenticationEntryPoint(context.getBean(KeycloakAuthenticationEntryPoint.class))
                .accessDeniedHandler(context.getBean(KeycloakAccessDeniedHandler.class)))
            // back-channel 로그아웃: Spring이 logout_token을 검증하고, 처리기는 sid의 세션 행을 지운다 (CSRF 필터보다 앞)
            .oidcLogout(o -> o.backChannel(b -> b.logoutHandler(context.getBean(KeycloakBackChannelLogoutHandler.class))))
            .oauth2Login(o -> {
                o.authorizationEndpoint(a -> a
                        .authorizationRequestRepository(context.getBean(KeycloakAuthorizationRequestRepository.class))
                        .authorizationRequestResolver(authorizationRequestResolver(context)))
                    .authorizedClientRepository(new KeycloakLoginAuthorizedClientRepository())
                    .userInfoEndpoint(u -> u.oidcUserService(oidcUserService()))
                    .successHandler(context.getBean(KeycloakLoginSuccessHandler.class))
                    .failureHandler(context.getBean(KeycloakLoginFailureHandler.class));
                login.customize(o);
            });
    }

    @Override
    public void configure(HttpSecurity http) {
        KeycloakAccessTokenFilter filter = accessTokenFilter(http.getSharedObject(ApplicationContext.class));
        filter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        filter.setSecurityContextRepository(new RequestAttributeSecurityContextRepository());
        http.addFilterBefore(postProcess(filter), BasicAuthenticationFilter.class);
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        http.addFilterBefore(postProcess(originFilter(context)), CsrfFilter.class);
        http.addFilterAfter(postProcess(csrfTokenEndpointFilter(context)), CsrfFilter.class);
        http.addFilterBefore(postProcess(new KeycloakLogoutMethodFilter(PathPatternRequestMatcher.withDefaults().matcher(LOGOUT_PATH),
            context.getBean(KeycloakErrorResponseWriter.class))), LogoutFilter.class);
        // Spring의 back-channel 필터도 CsrfFilter 앞에 들어간다. 이 설정기가 먼저 등록돼 같은 자리에서는 이 필터가 앞이다
        http.addFilterBefore(postProcess(new KeycloakBackChannelLogoutErrorFilter(
            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, BACK_CHANNEL_LOGOUT_PATH))), CsrfFilter.class);
        http.addFilterBefore(postProcess(mdcRequestFilter(context)), SecurityContextHolderFilter.class);
        MdcAuthenticationFilter mdcAuthentication = mdcAuthenticationFilter(context);
        mdcAuthentication.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        http.addFilterBefore(postProcess(mdcAuthentication), AuthorizationFilter.class);
    }

    /** 요청 정보 MDC 필터. */
    protected MdcRequestFilter mdcRequestFilter(ApplicationContext context) {
        KeycloakSecuritySettings settings = context.getBean(KeycloakSecuritySettings.class);
        return new MdcRequestFilter(context.getBean(LoggingContextAccessor.class), settings.logging(), settings.trustedProxyCount(),
            context.getBean(LoggingValueSanitizer.class));
    }

    /** 사용자 정보 MDC 필터. */
    protected MdcAuthenticationFilter mdcAuthenticationFilter(ApplicationContext context) {
        return new MdcAuthenticationFilter(context.getBean(LoggingContextAccessor.class),
            context.getBean(KeycloakSecuritySettings.class).logging(), context.getBean(LoggingValueSanitizer.class));
    }

    /** CORS 설정. 기본은 빈 {@value #CORS_CONFIGURATION_SOURCE_BEAN}. */
    protected CorsConfigurationSource corsConfigurationSource(ApplicationContext context) {
        return context.getBean(CORS_CONFIGURATION_SOURCE_BEAN, CorsConfigurationSource.class);
    }

    /** CSRF 토큰 처리기. 기본은 Spring의 Xor(응답마다 토큰을 가려 BREACH를 막는다). 헤더와 폼 칸을 모두 읽는다. */
    protected CsrfTokenRequestHandler csrfTokenRequestHandler() {
        return new XorCsrfTokenRequestAttributeHandler();
    }

    /** Keycloak이 서버에서 부르거나 Keycloak에서 돌아오는 주소. Origin·CSRF 확인에서 뺀다 (back-channel 로그아웃, OIDC 콜백). */
    protected RequestMatcher serverCallbacks() {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        return new OrRequestMatcher(paths.matcher("/logout/connect/back-channel/**"), paths.matcher("/login/oauth2/code/**"));
    }

    /** Origin 확인 필터. 빈으로 올리지 않는다 (서블릿 필터로 따로 등록되지 않게). */
    protected KeycloakOriginFilter originFilter(ApplicationContext context) {
        return new KeycloakOriginFilter(corsConfigurationSource(context), serverCallbacks(),
            context.getBean(KeycloakErrorResponseWriter.class));
    }

    /** {@code GET /api/csrf}. 경로는 {@code keycloak.security.csrf.endpoint}. */
    protected KeycloakCsrfTokenEndpointFilter csrfTokenEndpointFilter(ApplicationContext context) {
        return new KeycloakCsrfTokenEndpointFilter(context.getBean(KeycloakSecuritySettings.class).csrfEndpoint());
    }

    /**
     * 요청 인증 필터. 빈으로 올리지 않는다(서블릿 필터로 따로 등록되면 보안 체인 밖에서도 돌기 때문). 바꾸려면 이 메서드를 덮어쓰거나
     * 필터가 쓰는 빈({@link KeycloakAccessTokenValidator}, {@link KeycloakPrincipalConverter} 등)을 바꾼다.
     */
    protected KeycloakAccessTokenFilter accessTokenFilter(ApplicationContext context) {
        return new KeycloakAccessTokenFilter(
            context.getBean(KeycloakAccessTokenValidator.class),
            context.getBean(KeycloakPrincipalConverter.class),
            context.getBean(KeycloakCookieWriter.class),
            context.getBean(KeycloakLocalLogoutHandler.class),
            context.getBean(KeycloakErrorResponseWriter.class),
            context.getBean(KeycloakRefreshService.class),
            context.getBean(KeycloakSecuritySettings.class).backgroundHeader());
    }

    /** PKCE S256을 늘 붙인다 (client가 비공개여도). state·nonce는 Spring이 붙인다. */
    protected DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver(ApplicationContext context) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
            context.getBean(ClientRegistrationRepository.class),
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    /** 로그인 때 UserInfo를 부르지 않는다. 사용자 정보는 액세스 토큰에서 읽는다. */
    protected OidcUserService oidcUserService() {
        OidcUserService service = new OidcUserService();
        service.setRetrieveUserInfo(request -> false);
        return service;
    }
}
