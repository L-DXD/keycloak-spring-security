package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakLogoutHandler;
import com.ids.keycloak.security.authentication.OidcBackChannelSessionLogoutHandler;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.filter.KeycloakAuthenticationFilter;
import com.ids.keycloak.security.web.servlet.KeycloakAccessDeniedHandler;
import com.sd.KeycloakClient.factory.KeycloakClient;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

import static com.ids.keycloak.security.config.KeycloakSecurityConstants.BACK_CHANNEL_LOGOUT_URL;
import static com.ids.keycloak.security.config.KeycloakSecurityConstants.LOGOUT_URL;

/**
 * Keycloak 인증에 필요한 모든 핵심 설정을 {@link HttpSecurity}에 등록하는
 * {@link AbstractHttpConfigurer} 구현체입니다.
 * <p>
 * 이 Configurer는 다음을 설정합니다:
 * <ul>
 *   <li>인증 필터 (KeycloakAuthenticationFilter)</li>
 *   <li>인증 프로바이더 (KeycloakAuthenticationProvider)</li>
 *   <li>OIDC 로그인 (OAuth2Login)</li>
 *   <li>로그아웃 (Front-Channel, Back-Channel)</li>
 *   <li>예외 핸들러</li>
 *   <li>세션 관리</li>
 *   <li>CSRF (로그아웃 면제)</li>
 * </ul>
 * </p>
 * <p>
 * 사용자가 커스텀 SecurityFilterChain을 정의할 때 한 줄로 핵심 기능을 적용할 수 있습니다:
 * <pre>
 * http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());
 * </pre>
 * </p>
 * <p>
 * 인가 설정(authorizeHttpRequests)은 이 Configurer에서 처리하지 않습니다.
 * AutoConfiguration 또는 사용자 설정에서 직접 정의해야 합니다.
 * </p>
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

    @SuppressWarnings("unchecked")
    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // === Bean 조회 ===
        JwtDecoder jwtDecoder = context.getBean(JwtDecoder.class);
        KeycloakClient keycloakClient = context.getBean(KeycloakClient.class);
        ClientRegistrationRepository clientRegistrationRepository = context.getBean(ClientRegistrationRepository.class);
        FindByIndexNameSessionRepository<? extends Session> sessionRepository =
            context.getBean(FindByIndexNameSessionRepository.class);
        OAuth2AuthorizedClientRepository authorizedClientRepository = context.getBean(OAuth2AuthorizedClientRepository.class);
        OidcLoginSuccessHandler oidcLoginSuccessHandler = context.getBean(OidcLoginSuccessHandler.class);
        KeycloakLogoutHandler keycloakLogoutHandler = context.getBean(KeycloakLogoutHandler.class);
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = context.getBean(OidcClientInitiatedLogoutSuccessHandler.class);
        KeycloakSessionManager sessionManager = context.getBean(KeycloakSessionManager.class);

        // === 1. Authentication Provider 등록 ===
        KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider(
            jwtDecoder,
            keycloakClient,
            clientRegistrationRepository
        );
        http.authenticationProvider(provider);

        // === 2. 세션 관리 ===
        // Spring Security가 세션을 생성하지 않음 (애플리케이션에서 관리)
        http.sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        );

        // SecurityContext를 세션에 저장하지 않음 - 매 요청마다 KeycloakAuthenticationFilter가 인증 처리
        http.securityContext(securityContext -> securityContext
            .securityContextRepository(new NullSecurityContextRepository())
        );

        // === 3. OIDC 로그인 설정 ===
        http.oauth2Login(login -> login
            .successHandler(oidcLoginSuccessHandler)
            .authorizedClientRepository(authorizedClientRepository)
        );

        // === 4. 로그아웃 설정 ===
        // 4-1. Front-Channel 로그아웃 (사용자가 직접 로그아웃)
        http.logout(logout -> logout
            .logoutUrl(LOGOUT_URL)
            .addLogoutHandler(keycloakLogoutHandler)
            .logoutSuccessHandler(oidcLogoutSuccessHandler)
        );

        // 4-2. Back-Channel 로그아웃 (Keycloak에서 호출)
        // 엔드포인트: /logout/connect/back-channel/keycloak (자동 생성)
        OidcBackChannelSessionLogoutHandler backChannelLogoutHandler =
            new OidcBackChannelSessionLogoutHandler(sessionRepository);
        http.oidcLogout(oidc -> oidc
            .backChannel(backChannel -> backChannel
                .logoutHandler(backChannelLogoutHandler)
            )
        );

        // === 5. CSRF 설정 ===
        // 로그아웃 엔드포인트는 CSRF 면제 (OIDC 리다이렉트 시 토큰 전달 어려움)
        http.csrf(csrf -> csrf
            .ignoringRequestMatchers(LOGOUT_URL, BACK_CHANNEL_LOGOUT_URL)
        );
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // === Bean 조회 ===
        JwtDecoder jwtDecoder = context.getBean(JwtDecoder.class);
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        ObjectMapper objectMapper = context.getBean(ObjectMapper.class);
        KeycloakAuthenticationEntryPoint authenticationEntryPoint = context.getBean(KeycloakAuthenticationEntryPoint.class);
        KeycloakAccessDeniedHandler accessDeniedHandler = context.getBean(KeycloakAccessDeniedHandler.class);
        KeycloakSessionManager sessionManager = context.getBean(KeycloakSessionManager.class);

        // === 6. 예외 처리기 설정 ===
        http.exceptionHandling(customizer -> customizer
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(accessDeniedHandler)
        );

        // === 7. Keycloak 인증 필터 등록 ===
        KeycloakAuthenticationFilter authenticationFilter = new KeycloakAuthenticationFilter(
            jwtDecoder,
            authenticationManager,
            objectMapper,
            sessionManager
        );
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
