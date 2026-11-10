package com.ids.keycloak.security.web.config;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
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
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;
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
 *   <li>401·403은 JSON (로그인 화면으로 302하지 않는다)</li>
 *   <li>폼 로그인, Basic 인증을 끈다</li>
 * </ul>
 * 빈은 애플리케이션 컨텍스트에서 타입으로 찾는다. 스타터가 모두 올린다.
 */
public class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

    /** CORS 설정 빈 이름. 이 이름으로 올린 {@link CorsConfigurationSource}를 쓴다 (MVC의 다른 CORS 빈과 섞이지 않게 이름으로 찾는다). */
    public static final String CORS_CONFIGURATION_SOURCE_BEAN = "keycloakCorsConfigurationSource";

    /** 새 설정기. */
    public static KeycloakHttpConfigurer keycloak() {
        return new KeycloakHttpConfigurer();
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
            // 로그아웃은 #87(POST /logout, 리프레시 토큰 로그아웃)에서 붙인다
            .logout(AbstractHttpConfigurer::disable)
            .cors(c -> c.configurationSource(corsConfigurationSource(context)))
            .csrf(c -> c
                .csrfTokenRepository(context.getBean(CsrfTokenRepository.class))
                .csrfTokenRequestHandler(csrfTokenRequestHandler())
                // 로그인하면 로그인 처리기가 새 sid에 묶은 토큰을 쓴다. Spring의 "로그인 때 토큰 지우고 다시 만들기"는 쿠키를 두 번 쓰게 하므로 끈다
                .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
                .ignoringRequestMatchers(serverCallbacks()))
            .exceptionHandling(e -> e
                .authenticationEntryPoint(context.getBean(KeycloakAuthenticationEntryPoint.class))
                .accessDeniedHandler(context.getBean(KeycloakAccessDeniedHandler.class)))
            .oauth2Login(login -> login
                .authorizationEndpoint(a -> a
                    .authorizationRequestRepository(context.getBean(KeycloakAuthorizationRequestRepository.class))
                    .authorizationRequestResolver(authorizationRequestResolver(context)))
                .authorizedClientRepository(new KeycloakLoginAuthorizedClientRepository())
                .userInfoEndpoint(u -> u.oidcUserService(oidcUserService()))
                .successHandler(context.getBean(KeycloakLoginSuccessHandler.class))
                .failureHandler(context.getBean(KeycloakLoginFailureHandler.class)));
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
