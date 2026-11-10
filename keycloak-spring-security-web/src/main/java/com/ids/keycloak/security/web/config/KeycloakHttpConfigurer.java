package com.ids.keycloak.security.web.config;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;

import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.web.authentication.KeycloakAccessTokenFilter;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;
import com.ids.keycloak.security.web.error.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.web.error.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.web.login.KeycloakAuthorizationRequestRepository;
import com.ids.keycloak.security.web.login.KeycloakLoginAuthorizedClientRepository;
import com.ids.keycloak.security.web.login.KeycloakLoginFailureHandler;
import com.ids.keycloak.security.web.login.KeycloakLoginSuccessHandler;
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;

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
 *   <li>요청 인증: at 쿠키를 로컬 검증하는 {@link KeycloakAccessTokenFilter}를 Basic 인증 자리 앞에 넣는다</li>
 *   <li>401·403은 JSON (로그인 화면으로 302하지 않는다)</li>
 *   <li>폼 로그인, Basic 인증을 끈다</li>
 * </ul>
 * 빈은 애플리케이션 컨텍스트에서 타입으로 찾는다. 스타터가 모두 올린다.
 */
public class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

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
            // 로그아웃은 #87(POST /logout, 리프레시 토큰 로그아웃), CSRF는 #86(sid 서명 double-submit)에서 붙인다
            .logout(AbstractHttpConfigurer::disable)
            .csrf(AbstractHttpConfigurer::disable)
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
            context.getBean(KeycloakErrorResponseWriter.class));
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
