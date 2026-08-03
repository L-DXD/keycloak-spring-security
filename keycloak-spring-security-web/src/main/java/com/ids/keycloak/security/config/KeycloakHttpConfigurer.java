package com.ids.keycloak.security.config;

import com.ids.keycloak.security.authentication.BasicAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.authentication.KeycloakLogoutHandler;
import com.ids.keycloak.security.authentication.OidcBackChannelSessionLogoutHandler;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.filter.BasicAuthenticationFilter;
import com.ids.keycloak.security.filter.KeycloakAuthenticationFilter;
import com.ids.keycloak.security.filter.MdcAuthenticationFilter;
import com.ids.keycloak.security.filter.MdcRequestFilter;
import com.ids.keycloak.security.filter.RateLimitFilter;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.WebMdcContextAccessor;
import com.ids.keycloak.security.exception.KeycloakAccessDeniedHandler;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

import static com.ids.keycloak.security.config.KeycloakSecurityConstants.BACK_CHANNEL_LOGOUT_URL;
import static com.ids.keycloak.security.config.KeycloakSecurityConstants.LOGOUT_URL;

/**
 * Keycloak 인증에 필요한 모든 핵심 설정을 {@link HttpSecurity}에 등록하는 {@link AbstractHttpConfigurer} 구현체입니다.
 * <p>
 * 이 Configurer는 다음을 설정합니다:
 * <ul>
 *   <li>MDC 로깅 필터 (MdcRequestFilter, MdcAuthenticationFilter)</li>
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
@Slf4j
public final class KeycloakHttpConfigurer extends AbstractHttpConfigurer<KeycloakHttpConfigurer, HttpSecurity> {

   private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

   private KeycloakHttpConfigurer() {
   }

   /**
    * Configurer 인스턴스를 생성하는 정적 팩토리 메서드입니다.
    */
   public static KeycloakHttpConfigurer keycloak() {
      return new KeycloakHttpConfigurer();
   }

   /**
    * 세션 리포지토리를 명시적으로 설정합니다.
    * <p>
    * 자동 설정(AutoConfiguration)에서 의존성 주입 받은 빈을 전달할 때 사용합니다. 이를 통해 빈 생성 순서 문제를 해결할 수 있습니다.
    * </p>
    */
   public KeycloakHttpConfigurer sessionRepository(FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
      this.sessionRepository = sessionRepository;
      return this;
   }

   @SuppressWarnings("unchecked")
   @Override
   public void init(HttpSecurity http) throws Exception {
      ApplicationContext context = http.getSharedObject(ApplicationContext.class);

      // === Bean 조회 ===
      KeycloakClient keycloakClient = context.getBean(KeycloakClient.class);
      ClientRegistrationRepository clientRegistrationRepository = context.getBean(ClientRegistrationRepository.class);

      // 세션 리포지토리가 명시적으로 설정되지 않았다면 컨텍스트에서 조회 시도 (ObjectProvider 사용)
      if (this.sessionRepository == null) {
         this.sessionRepository = context.getBeanProvider(FindByIndexNameSessionRepository.class).getIfAvailable();
      }

      OAuth2AuthorizedClientRepository authorizedClientRepository = context.getBean(OAuth2AuthorizedClientRepository.class);
      OidcLoginSuccessHandler oidcLoginSuccessHandler = context.getBean(OidcLoginSuccessHandler.class);
      KeycloakLogoutHandler keycloakLogoutHandler = context.getBean(KeycloakLogoutHandler.class);
      OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = context.getBean(OidcClientInitiatedLogoutSuccessHandler.class);
      KeycloakSessionManager sessionManager = context.getBean(KeycloakSessionManager.class);

        // === 1. Authentication Provider 등록 ===
        String clientId = clientRegistrationRepository.findByRegistrationId("keycloak").getClientId();
        // 보안 Advisory 1: ID/Access Token 서명 검증 및 토큰 결합 검증용 JwtDecoder
        // High #2: 타입(JwtDecoder.class)이 아닌 keycloakOidcJwtDecoder 빈 이름으로 조회한다.
        // 애플리케이션이 다른 issuer/resource-server용 JwtDecoder를 등록해도 이 전용 decoder를
        // 정확히 지목하며, NoUniqueBeanDefinitionException 위험도 없앤다.
        JwtDecoder jwtDecoder = context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class);
        KeycloakAuthenticationProvider provider =
            new KeycloakAuthenticationProvider(keycloakClient, clientId, jwtDecoder);
        // M-2: require-user-info 토글 적용 (기본 false = 기존 동작 유지, 회귀 0)
        KeycloakSecurityProperties securityPropertiesForProvider = context.getBean(KeycloakSecurityProperties.class);
        provider.setRequireUserInfo(securityPropertiesForProvider.getAuthentication().isRequireUserInfo());
        // 보안 Advisory 7: Realm/Client 역할 네임스페이스 분리 설정 적용 (기본 SEPARATE_NAMESPACE)
        provider.setRoleMapping(securityPropertiesForProvider.getRoleMapping());
        http.authenticationProvider(provider);

      // === 2. 세션 관리 ===
      // Spring Security가 세션을 생성하지 않음 (애플리케이션에서 관리)
      // 보안 Advisory 2: Session Fixation Protection — OIDC 로그인 성공 시 기존 세션 ID를 그대로
      // 유지하던 sf.none() 설정을 제거하고, 인증 성공 시 changeSessionId()로 세션 ID를 회전한다.
      // (OAuth2LoginAuthenticationFilter가 OidcLoginSuccessHandler를 호출하기 전에
      //  AbstractAuthenticationProcessingFilter#successfulAuthentication에서 세션 전략이 먼저 적용되므로,
      //  Refresh Token/Principal Name/Keycloak sid는 항상 회전된 새 세션 ID에 저장된다.)
      // SessionCreationPolicy.NEVER 환경에서도 안전: 인증 전 세션이 없으면 changeSessionId는 아무 것도
      // 하지 않는다(AbstractSessionFixationProtectionStrategy#onAuthentication 참고).
      http.sessionManagement(session -> session
          .sessionCreationPolicy(SessionCreationPolicy.NEVER)
          .sessionFixation(sessionFixation -> sessionFixation.changeSessionId())
      );

      // Filter에서 사용할 수 있도록 SharedObject로 저장
      http.setSharedObject(KeycloakAuthenticationProvider.class, provider);
      http.setSharedObject(KeycloakClient.class, keycloakClient);

      // SecurityContext 저장 정책 (기본값 NULL = 세션에 저장하지 않음, 기존 동작 유지, 회귀 0).
      // 매 요청마다 KeycloakAuthenticationFilter가 OIDC 쿠키로부터 인증을 재계산하므로 기본값(NULL)
      // 상태에서도 OIDC 쿠키 인증 자체엔 영향이 없다. 다만 이 필터 체인보다 앞서 실행되는 필터
      // (예: 애플리케이션이 직접 등록한 FilterRegistrationBean 기반 핸드오프 필터)가 세워둔 인증을
      // 보존해야 하는 소비자는 keycloak.security.authentication.security-context-repository를
      // HTTP_SESSION(또는 DELEGATING)으로 opt-in할 수 있다. 자세한 근거는
      // SecurityContextRepositoryMode Javadoc 참고.
      SecurityContextRepositoryMode securityContextRepositoryMode =
          securityPropertiesForProvider.getAuthentication().getSecurityContextRepository();
      http.securityContext(securityContext -> securityContext
          .securityContextRepository(resolveSecurityContextRepository(securityContextRepositoryMode))
      );

      // === 3. OIDC 로그인 설정 ===
      // AuthorizationRequestResolver: 사용자 등록 빈 우선, 없으면 기본 resolver 사용
      OAuth2AuthorizationRequestResolver authorizationRequestResolver =
          context.getBeanProvider(OAuth2AuthorizationRequestResolver.class).getIfAvailable();

      http.oauth2Login(login -> {
          login.successHandler(oidcLoginSuccessHandler)
               .authorizedClientRepository(authorizedClientRepository);
          if (authorizationRequestResolver != null) {
              login.authorizationEndpoint(ep ->
                  ep.authorizationRequestResolver(authorizationRequestResolver));
          }
      });

      // === 3-1. 예외 처리기 설정 (버그 수정: init() 단계에서 등록) ===
      // 배경: http.oauth2Login(...) 호출은 내부적으로 OAuth2LoginConfigurer를 등록하고,
      // 그 OAuth2LoginConfigurer#init()이 ExceptionHandlingConfigurer#defaultAuthenticationEntryPointFor(...)를
      // 호출해 "기본 로그인 페이지로 리다이렉트하는 EntryPoint"를 defaultEntryPointMappings에 등록한다.
      // Spring Security의 HttpSecurity(AbstractConfiguredSecurityBuilder)는 모든 Configurer의 init()이
      // 끝난 뒤에야 모든 Configurer의 configure()를 실행하므로, 과거처럼 이 설정을 (아래 있던) configure()에서
      // exceptionHandling(...).authenticationEntryPoint(...)로 설정하면, 그 시점엔 이미
      // ExceptionHandlingConfigurer#configure()가 (Map 등록 순서상 훨씬 앞서) 실행되어
      // ExceptionTranslationFilter가 defaultEntryPointMappings 기반 EntryPoint로 확정된 뒤였다
      // (ExceptionHandlingConfigurer는 Spring Boot의 HttpSecurityConfiguration#httpSecurity()에서
      // .exceptionHandling(withDefaults())로 아주 이른 시점에 등록되므로, configurers 맵 순서상
      // 우리 KeycloakHttpConfigurer.configure()보다 먼저 자신의 configure()가 실행된다).
      // ExceptionHandlingConfigurer#getAuthenticationEntryPoint(H)/#getAccessDeniedHandler(H)는
      // authenticationEntryPoint/accessDeniedHandler 필드가 설정되어 있으면 defaultEntryPointMappings
      // /defaultDeniedHandlerMappings를 무시하고 그 필드 값을 우선 사용한다. init() 단계는 모든 Configurer의
      // configure()보다 항상 먼저 끝나므로, 여기서 필드를 설정해두면 등록 순서와 무관하게 항상 우리 값이 이긴다.
      KeycloakAuthenticationEntryPoint authenticationEntryPoint = context.getBean(KeycloakAuthenticationEntryPoint.class);
      KeycloakAccessDeniedHandler accessDeniedHandler = context.getBean(KeycloakAccessDeniedHandler.class);
      http.exceptionHandling(customizer -> customizer
          .authenticationEntryPoint(authenticationEntryPoint)
          .accessDeniedHandler(accessDeniedHandler)
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
          new OidcBackChannelSessionLogoutHandler(this.sessionRepository);
      http.oidcLogout(oidc -> oidc
          .backChannel(backChannel -> backChannel
              .logoutHandler(backChannelLogoutHandler)
          )
      );

      // === 5. CSRF 설정 ===
      KeycloakSecurityProperties securityProperties = context.getBean(KeycloakSecurityProperties.class);
      KeycloakBearerTokenProperties bearerTokenProperties = securityProperties.getBearerToken();
      KeycloakCsrfProperties csrfProperties = securityProperties.getCsrf();

      if (!csrfProperties.isEnabled()) {
          // CSRF 완전 비활성화
          http.csrf(AbstractHttpConfigurer::disable);
          log.info("CSRF 비활성화");
      } else {
          // 기본 면제 경로
          List<String> ignorePaths = new ArrayList<>();
          // Back-Channel 로그아웃은 Keycloak 서버→서버 요청이므로 항상 면제
          ignorePaths.add(BACK_CHANNEL_LOGOUT_URL);

          // Bearer Token 경로 면제:
          //   /token, /refresh — 비인증 자격증명 제출 엔드포인트이므로 항상 면제
          //   /logout(prefix)  — Bearer Token 전용 로그아웃 API. Bearer 토큰으로만 호출되므로
          //                      (브라우저 폼 세션과 무관) Bearer Token 활성 시 면제
          if (bearerTokenProperties.isEnabled()) {
              String prefix = bearerTokenProperties.getTokenEndpoint().getPrefix();
              ignorePaths.add(prefix + "/token");
              ignorePaths.add(prefix + "/refresh");
              ignorePaths.add(prefix + "/logout");
          }

          // 보안 Medium #4: 브라우저 Front-Channel 로그아웃(LOGOUT_URL, 기본 "/logout")은
          // Bearer Token 전용 로그아웃(prefix + "/logout")과 별개의 엔드포인트이며, 항상
          // CSRF 보호를 유지한다(Bearer Token 활성 여부와 무관). 이 경로는 브라우저 쿠키 기반
          // OIDC 세션을 종료하는 폼 POST 엔드포인트이므로, 여기를 CSRF 면제 목록에 포함시키면
          // 공격 사이트가 크로스사이트 POST로 로그인된 사용자를 강제 로그아웃시킬 수 있다
          // (CSRF, CWE-352). 따라서 어떤 조건에서도 LOGOUT_URL을 ignorePaths에 추가하지 않는다.
          log.debug("/logout(LOGOUT_URL) CSRF 보호 항상 활성화 (Bearer Token 활성 여부와 무관, 면제 목록에서 제외)");

          // 사용자 지정 면제 경로 추가
          ignorePaths.addAll(csrfProperties.getIgnorePaths());

          // RequestMatcher 리스트 구성
          List<RequestMatcher> ignoreMatchers = new ArrayList<>();
          for (String path : ignorePaths) {
              ignoreMatchers.add(new AntPathRequestMatcher(path));
          }

          // 보안 Advisory 3: Authorization: Basic 헤더 보유 여부만으로 CSRF를 전면 면제하지 않는다.
          // 브라우저가 HTTP Basic 자격증명을 캐시해 자동 재전송하면(ambient credential),
          // cross-origin 폼 제출이 캐시된 Basic 자격증명을 실은 채 CSRF 검증을 우회할 수 있다
          // (CWE-352). Authorization 헤더 존재는 "비-브라우저 요청"의 증거가 될 수 없다.
          // 머신 전용 API 등 CSRF 면제가 필요한 경로는 위 csrfProperties.ignorePaths에
          // 명시적으로 등록해야 한다(전면 면제 금지, 명시 allowlist만 허용).

          http.csrf(csrf -> csrf
              .ignoringRequestMatchers(ignoreMatchers.toArray(new RequestMatcher[0]))
          );
          log.info("CSRF 활성화 (면제 경로: {})", ignorePaths);
      }

      // === 6. Bearer Token Resource Server 설정 (Introspect 온라인 검증) ===
      if (bearerTokenProperties.isEnabled()) {
          log.info("Bearer Token 인증 활성화 (검증 방식: introspect)");

          OpaqueTokenIntrospector introspector = context.getBean(OpaqueTokenIntrospector.class);
          http.oauth2ResourceServer(rs -> rs
              .opaqueToken(opaque -> opaque
                  .introspector(introspector)
              )
          );
      }
   }

   @Override
   public void configure(HttpSecurity http) throws Exception {
      ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // === Bean 및 SharedObject 조회 ===
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        KeycloakAuthenticationProvider authenticationProvider = http.getSharedObject(KeycloakAuthenticationProvider.class);
        KeycloakClient keycloakClient = http.getSharedObject(KeycloakClient.class);
        KeycloakSessionManager sessionManager = context.getBean(KeycloakSessionManager.class);
        KeycloakSecurityProperties securityProperties = context.getBean(KeycloakSecurityProperties.class);

        // LoggingContextAccessor: Bean이 있으면 사용, 없으면 기본 구현체 사용
        LoggingContextAccessor loggingContextAccessor = getBeanOrDefault(
            context, LoggingContextAccessor.class, new WebMdcContextAccessor());

        // 예외 처리기(EntryPoint/AccessDeniedHandler) 등록은 init()의 "3-1. 예외 처리기 설정"으로 이동했다.
        // (버그: configure()에서 등록하면 ExceptionHandlingConfigurer#configure()가 먼저 실행되어 무시됨)

        // 7. MDC 로깅 필터 등록
        // 7-1. MdcRequestFilter: 인증 전 (최상단) - traceId, httpMethod, requestUri, clientIp, query, userAgent
        // 민감정보 마스킹은 LoggingValueSanitizer 빈에 위임(없으면 기본 PII 마스킹)
        LoggingValueSanitizer loggingValueSanitizer = getBeanOrDefault(
            context, LoggingValueSanitizer.class, new DefaultPiiMaskingSanitizer());
        MdcRequestFilter mdcRequestFilter = new MdcRequestFilter(loggingContextAccessor, securityProperties, loggingValueSanitizer);
        http.addFilterBefore(mdcRequestFilter, SecurityContextHolderFilter.class);

        // 7-2. MdcAuthenticationFilter: 인증 후 (AuthorizationFilter 앞) - userId, username, sessionId
        MdcAuthenticationFilter mdcAuthenticationFilter = new MdcAuthenticationFilter(loggingContextAccessor, securityProperties);
        http.addFilterBefore(mdcAuthenticationFilter, AuthorizationFilter.class);

        // === 8. Keycloak 인증 필터 등록 ===
        // Bearer Token 활성화 시 토큰 발급 API 경로를 필터 스킵 대상에 추가
        List<String> skipPaths = new ArrayList<>();
        if (securityProperties.getBearerToken().isEnabled()) {
            String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
            skipPaths.add(prefix + "/token");
            skipPaths.add(prefix + "/refresh");
            skipPaths.add(prefix + "/logout");
            log.debug("KeycloakAuthenticationFilter 스킵 경로 설정: {}", skipPaths);
        }

        List<String> loginPaths = securityProperties.getAuthentication().getLoginPaths();

        KeycloakAuthenticationFilter authenticationFilter = new KeycloakAuthenticationFilter(
            authenticationManager,
            authenticationProvider,
            sessionManager,
            keycloakClient,
            skipPaths,
            loginPaths
        );
        authenticationFilter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // === 9. Basic Auth 필터 등록 (조건부) ===
        if (securityProperties.getBasicAuth().isEnabled()) {
            BasicAuthenticationFilter basicAuthFilter = new BasicAuthenticationFilter(authenticationManager);
            basicAuthFilter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());
            http.addFilterBefore(basicAuthFilter, KeycloakAuthenticationFilter.class);
        }

        // === 10. Rate Limit 필터 등록 (조건부) ===
        if (securityProperties.getRateLimit().isEnabled()) {
            RateLimiter rateLimiter = getBeanOrDefault(context, RateLimiter.class, null);
            if (rateLimiter != null) {
                List<String> rateLimitPaths = new ArrayList<>();
                if (securityProperties.getBearerToken().isEnabled()) {
                    String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
                    rateLimitPaths.add(prefix + "/token");
                }
                RateLimitFilter rateLimitFilter = new RateLimitFilter(
                    rateLimiter, securityProperties.getRateLimit(), rateLimitPaths
                );
                rateLimitFilter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());
                // BasicAuthenticationFilter보다 앞에 위치 (차단된 요청은 인증 시도 자체를 하지 않음)
                http.addFilterBefore(rateLimitFilter, BasicAuthenticationFilter.class);
                log.info("Rate Limit 필터 등록 완료 (대상 경로: {}, Basic Auth 포함: {})",
                    rateLimitPaths, securityProperties.getRateLimit().isIncludeBasicAuth());
            } else {
                log.warn("Rate Limit이 활성화되었으나 RateLimiter 빈을 찾을 수 없습니다.");
            }
        }
    }

    /**
     * ApplicationContext에서 Bean을 조회하고, 없으면 기본값을 반환합니다.
     */
    private <T> T getBeanOrDefault(ApplicationContext context, Class<T> beanClass, T defaultValue) {
        try {
            return context.getBean(beanClass);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    /**
     * {@code keycloak.security.authentication.security-context-repository} 설정값에 해당하는
     * {@link SecurityContextRepository} 인스턴스를 생성합니다.
     *
     * @param mode 저장 정책 (기본값 {@link SecurityContextRepositoryMode#NULL})
     * @return 선택된 정책에 해당하는 {@link SecurityContextRepository}
     * @see SecurityContextRepositoryMode
     */
    private SecurityContextRepository resolveSecurityContextRepository(SecurityContextRepositoryMode mode) {
        SecurityContextRepositoryMode effectiveMode = mode != null ? mode : SecurityContextRepositoryMode.NULL;
        switch (effectiveMode) {
            case HTTP_SESSION -> log.info("SecurityContextRepository: HTTP_SESSION (앞단 필터·핸드오프 인증 보존)");
            case DELEGATING -> log.info("SecurityContextRepository: DELEGATING (RequestAttribute + HttpSession)");
            case NULL -> { /* 기본값, 로깅하지 않음(기존 동작) */ }
        }
        // KeycloakLoginService(프로그래밍 방식 로그인)와 동일한 생성 로직을 공유한다.
        return SecurityContextRepositoryFactory.create(effectiveMode);
    }
}
