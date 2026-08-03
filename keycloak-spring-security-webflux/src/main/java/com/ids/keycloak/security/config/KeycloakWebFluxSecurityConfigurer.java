package com.ids.keycloak.security.config;

import com.ids.keycloak.security.authentication.KeycloakReactiveAuthenticationManager;
import com.ids.keycloak.security.authentication.KeycloakReactiveLogoutHandler;
import com.ids.keycloak.security.authentication.KeycloakReactiveOpaqueTokenIntrospector;
import com.ids.keycloak.security.authentication.KeycloakServerAuthenticationConverter;
import com.ids.keycloak.security.authentication.OidcReactiveLoginSuccessHandler;
import com.ids.keycloak.security.filter.ReactiveAuthLoggingFilter;
import com.ids.keycloak.security.filter.ReactiveBackChannelLogoutEndpointFilter;
import com.ids.keycloak.security.filter.ReactiveBasicAuthenticationFilter;
import com.ids.keycloak.security.filter.ReactiveLoggingFilter;
import com.ids.keycloak.security.filter.ReactiveRateLimitFilter;
import com.ids.keycloak.security.manager.KeycloakReactiveAuthorizationManager;
import com.ids.keycloak.security.config.KeycloakBearerTokenProperties;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.ReactiveCookieUtil;
import com.ids.keycloak.security.web.reactive.KeycloakServerAccessDeniedHandler;
import com.ids.keycloak.security.web.reactive.KeycloakServerAuthenticationEntryPoint;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Keycloak 인증에 필요한 설정을 {@link ServerHttpSecurity}에 조립하는 헬퍼 클래스입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakHttpConfigurer}에 대응하는 WebFlux 구현체입니다.
 * OIDC 로그인, 세션 연동, 로깅, 인가, Bearer Token, Basic Auth, Rate Limiting, CSRF,
 * Front-Channel/Back-Channel 로그아웃을 조건부로 설정합니다.</p>
 */
@Slf4j
public final class KeycloakWebFluxSecurityConfigurer {

  private KeycloakWebFluxSecurityConfigurer() {
  }

  /**
   * 전체 Keycloak 보안 설정이 적용된 {@link SecurityWebFilterChain}을 빌드합니다.
   *
   * @param http                      {@link ServerHttpSecurity} 인스턴스
   * @param authenticationManager     {@link KeycloakReactiveAuthenticationManager}
   * @param entryPoint                인증 실패 핸들러
   * @param accessDeniedHandler       인가 실패 핸들러
   * @param securityProperties        Keycloak 보안 설정
   * @param keycloakClient            Keycloak 클라이언트
   * @param clientId                  OAuth2 클라이언트 ID
   * @param sessionManager            Reactive 세션 매니저
   * @param rateLimiter               Rate Limiter (null 가능, null이면 Rate Limit 비활성)
   * @param loggingFilter             로깅 WebFilter (null 가능)
   * @param authLoggingFilter         인증 로깅 WebFilter (null 가능)
   * @param clientRegistrationRepo    ReactiveClientRegistrationRepository (OIDC 로그인/로그아웃용)
   * @param authorizedClientService   ReactiveOAuth2AuthorizedClientService (토큰 조회용)
   * @param backChannelFilter              BackChannel 로그아웃 필터 (null 가능 — Spring Session 없으면 null)
   * @param authorizationRequestResolver   OIDC authorize 요청 파라미터 커스터마이즈 resolver (null 가능 — null이면 기본 동작)
   * @return 구성된 {@link SecurityWebFilterChain}
   */
  public static SecurityWebFilterChain configure(
      ServerHttpSecurity http,
      ReactiveAuthenticationManager authenticationManager,
      KeycloakServerAuthenticationEntryPoint entryPoint,
      KeycloakServerAccessDeniedHandler accessDeniedHandler,
      KeycloakSecurityProperties securityProperties,
      KeycloakClient keycloakClient,
      String clientId,
      ReactiveSessionManager sessionManager,
      RateLimiter rateLimiter,
      ReactiveLoggingFilter loggingFilter,
      ReactiveAuthLoggingFilter authLoggingFilter,
      ReactiveClientRegistrationRepository clientRegistrationRepo,
      ReactiveOAuth2AuthorizedClientService authorizedClientService,
      ReactiveBackChannelLogoutEndpointFilter backChannelFilter,
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver) throws Exception {

    // 1. SecurityContext를 세션에 저장하지 않음 — 매 요청마다 필터가 인증 처리
    http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

    // 2. 예외 처리기 등록
    http.exceptionHandling(spec -> spec
        .authenticationEntryPoint(entryPoint)
        .accessDeniedHandler(accessDeniedHandler)
    );

    // 3. 로깅 필터 등록
    if (loggingFilter != null) {
      http.addFilterAt(loggingFilter, SecurityWebFiltersOrder.FIRST);
      log.debug("[Configurer] ReactiveLoggingFilter 등록 완료.");
    }
    if (authLoggingFilter != null) {
      http.addFilterAfter(authLoggingFilter, SecurityWebFiltersOrder.AUTHENTICATION);
      log.debug("[Configurer] ReactiveAuthLoggingFilter 등록 완료.");
    }

    // 4. Back-Channel 로그아웃 필터 명시 등록 (H-2: 전역 WebFilter 빈 대신 체인 내 명시 등록)
    if (backChannelFilter != null) {
      http.addFilterAt(backChannelFilter, SecurityWebFiltersOrder.FIRST);
      log.info("[Configurer] ReactiveBackChannelLogoutEndpointFilter 등록 완료.");
    }

    // 5. Rate Limit 필터 등록 (조건부)
    KeycloakRateLimitProperties rateLimitProps = securityProperties.getRateLimit();
    if (rateLimitProps.isEnabled() && rateLimiter != null) {
      List<String> rateLimitPaths = new ArrayList<>();
      if (securityProperties.getBearerToken().isEnabled()) {
        String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
        rateLimitPaths.add(prefix + "/token");
      }
      ReactiveRateLimitFilter rateLimitFilter = new ReactiveRateLimitFilter(
          rateLimiter, rateLimitProps, rateLimitPaths);
      rateLimitFilter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());
      http.addFilterBefore(rateLimitFilter, SecurityWebFiltersOrder.HTTP_BASIC);
      log.info("[Configurer] Rate Limit 필터 등록 완료 (대상 경로: {}, Basic 포함: {})",
          rateLimitPaths, rateLimitProps.isIncludeBasicAuth());
    }

    // 6. Basic Auth 필터 등록 (조건부)
    if (securityProperties.getBasicAuth().isEnabled()) {
      ReactiveBasicAuthenticationFilter basicAuthFilter =
          new ReactiveBasicAuthenticationFilter(keycloakClient, clientId);
      basicAuthFilter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());
      // 보안 Advisory 7: Realm/Client 역할 네임스페이스 분리 설정 적용 (기본 SEPARATE_NAMESPACE)
      basicAuthFilter.setRoleMapping(securityProperties.getRoleMapping());
      http.addFilterAt(basicAuthFilter, SecurityWebFiltersOrder.HTTP_BASIC);
      log.info("[Configurer] Basic Auth 필터 등록 완료.");
    }

    // 7. OIDC 쿠키 인증 필터 (AuthenticationWebFilter) 등록
    if (!(authenticationManager instanceof KeycloakReactiveAuthenticationManager)) {
      throw new IllegalStateException(
          "authenticationManager must be KeycloakReactiveAuthenticationManager but was: "
              + authenticationManager.getClass().getName());
    }
    KeycloakServerAuthenticationConverter converter = new KeycloakServerAuthenticationConverter(
        (KeycloakReactiveAuthenticationManager) authenticationManager,
        keycloakClient,
        sessionManager,
        securityProperties.getCookie());
    converter.setTrustedProxyCount(securityProperties.getTrustedProxyCount());

    AuthenticationWebFilter authFilter = new AuthenticationWebFilter(authenticationManager);
    authFilter.setServerAuthenticationConverter(converter);

    // 항목 3 / C-2: 정적 리소스는 AuthenticationWebFilter의 컨버터 실행 자체를 건너뛴다(성능
    // 목적). permitAll(아래 configureAuthorization)만으로는 이 필터가 여전히 실행되어
    // KeycloakServerAuthenticationConverter가 매 요청 introspect/UserInfo 원격 호출을 시도하므로
    // (로그인 세션이 있는 사용자 기준), 필터 단계에서도 함께 제외해야 근본 원인이 해소된다(servlet
    // 모듈의 KeycloakAuthenticationFilter skipPaths와 동일 개념). 인가에는 영향이 없다 —
    // permitAll 여부와는 별도 축(filterSkip)으로 판단하므로, 이 경로가 실제 보호 리소스라면
    // anyExchange().authenticated()에 의해 여전히 차단된다.
    KeycloakStaticResourceProperties staticResourceProperties = securityProperties.getStaticResources();
    if (staticResourceProperties.isFilterSkipEffective() && !staticResourceProperties.getPatterns().isEmpty()) {
      ServerWebExchangeMatcher staticResourceMatcher = toOrMatcher(staticResourceProperties.getPatterns());
      authFilter.setRequiresAuthenticationMatcher(new AndServerWebExchangeMatcher(
          ServerWebExchangeMatchers.anyExchange(),
          new NegatedServerWebExchangeMatcher(staticResourceMatcher)));
      log.info("[Configurer] 정적 리소스는 AuthenticationWebFilter 처리 대상에서 제외: {}",
          staticResourceProperties.getPatterns());
    }

    http.addFilterAt(authFilter, SecurityWebFiltersOrder.AUTHENTICATION);
    log.debug("[Configurer] AuthenticationWebFilter (OIDC Cookie) 등록 완료.");

    // 8. CSRF 설정
    configureCsrf(http, securityProperties);

    // 9. Bearer Token Resource Server 설정 (조건부)
    if (securityProperties.getBearerToken().isEnabled()) {
      KeycloakReactiveOpaqueTokenIntrospector introspector =
          new KeycloakReactiveOpaqueTokenIntrospector(keycloakClient, clientId);
      // 보안 Advisory 7: Realm/Client 역할 네임스페이스 분리 설정 적용 (기본 SEPARATE_NAMESPACE)
      introspector.setRoleMapping(securityProperties.getRoleMapping());
      http.oauth2ResourceServer(rs -> rs
          .opaqueToken(opaque -> opaque.introspector(introspector))
      );
      log.info("[Configurer] Bearer Token Resource Server (Introspect) 등록 완료.");
    }

    // 10. OIDC 로그인 (C-1) — Spring Security oauth2Login + 성공 핸들러
    if (clientRegistrationRepo != null && authorizedClientService != null) {
      String defaultSuccessUrl = securityProperties.getAuthentication().getDefaultSuccessUrl();
      OidcReactiveLoginSuccessHandler oidcSuccessHandler = new OidcReactiveLoginSuccessHandler(
          authorizedClientService,
          sessionManager,
          securityProperties.getCookie(),
          defaultSuccessUrl != null ? defaultSuccessUrl : "/");

      http.oauth2Login(login -> {
          login.authenticationSuccessHandler(oidcSuccessHandler);
          if (authorizationRequestResolver != null) {
              login.authorizationRequestResolver(authorizationRequestResolver);
          }
      });
      log.info("[Configurer] OIDC oauth2Login 등록 완료 (defaultSuccessUrl={}).", defaultSuccessUrl);
    } else {
      log.debug("[Configurer] ReactiveClientRegistrationRepository 또는 "
          + "ReactiveOAuth2AuthorizedClientService가 없어 oauth2Login을 건너뜁니다.");
    }

    // 11. 로그아웃 설정
    // 11-1. Front-Channel 로그아웃 핸들러
    KeycloakReactiveLogoutHandler logoutHandler = new KeycloakReactiveLogoutHandler(
        keycloakClient, sessionManager, securityProperties.getCookie());

    // 11-2. RP-Initiated 로그아웃 (C-3) — OidcClientInitiatedServerLogoutSuccessHandler
    if (clientRegistrationRepo != null) {
      OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutHandler =
          new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepo);
      oidcLogoutHandler.setPostLogoutRedirectUri("{baseUrl}");

      http.logout(logout -> logout
          .logoutUrl(KeycloakWebFluxConstants.LOGOUT_URL)
          .logoutHandler(logoutHandler)
          .logoutSuccessHandler(oidcLogoutHandler)
      );
      log.info("[Configurer] RP-Initiated 로그아웃(OidcClientInitiatedServerLogoutSuccessHandler) 등록 완료.");
    } else {
      http.logout(logout -> logout
          .logoutUrl(KeycloakWebFluxConstants.LOGOUT_URL)
          .logoutHandler(logoutHandler)
      );
      log.debug("[Configurer] 기본 로그아웃 핸들러 등록 완료.");
    }

    // 12. 인가 설정
    configureAuthorization(http, securityProperties, keycloakClient);

    return http.build();
  }

  /**
   * CSRF 설정을 적용합니다.
   *
   * <p>API 서버 기본값은 disabled. CSRF 활성화 시 {@code requireCsrfProtectionMatcher}는
   * <b>{@link CsrfWebFilter#DEFAULT_CSRF_MATCHER}(GET/HEAD/TRACE/OPTIONS 등 안전 메서드 제외)</b>와
   * <b>면제 경로 부정 매처(NegatedServerWebExchangeMatcher)</b>를 AND로 결합해 지정합니다.
   * 안전 메서드까지 CSRF 보호 대상으로 잘못 지정되면 일반 GET 요청, OIDC 로그인 콜백,
   * 정적 리소스, 리다이렉트 등이 403으로 차단될 수 있으므로 반드시 두 조건을 함께 적용해야
   * 합니다.</p>
   *
   * <p><b>면제 대상:</b>
   * <ul>
   *   <li>Back-Channel 로그아웃 경로 — POST+exact 경로 한정 (M-2 보강)</li>
   *   <li>Bearer Token 엔드포인트 경로 (토큰 발급/갱신, Bearer 전용 로그아웃)</li>
   *   <li>사용자 지정 ignorePaths</li>
   * </ul>
   * <b>면제 대상 아님(항상 CSRF 보호):</b> 브라우저 Front-Channel 로그아웃 경로
   * ({@link KeycloakWebFluxConstants#LOGOUT_URL}, 기본 {@code /logout}). Bearer 전용
   * 로그아웃(prefix + {@code /logout})과는 별개의 엔드포인트이며, Bearer Token 활성 여부와
   * 무관하게 CSRF 면제 목록에서 제외한다(보안 Medium #4, CWE-352 — 브라우저 강제 로그아웃 방지).
   * </p>
   *
   * <p><b>보안 Advisory 3:</b> {@code Authorization: Basic} 헤더 보유 여부만으로 CSRF를 전면
   * 면제하지 않는다. 브라우저가 HTTP Basic 자격증명을 캐시해 자동 재전송하면(ambient credential),
   * cross-origin 폼 제출이 캐시된 Basic 자격증명을 실은 채 CSRF 검증을 우회할 수 있다(CWE-352).
   * Authorization 헤더 존재는 "비-브라우저 요청"의 증거가 될 수 없다. 머신 전용 API 등 CSRF
   * 면제가 필요한 경로는 {@code csrfProperties.ignorePaths}에 명시적으로 등록해야 한다
   * (전면 면제 금지, 명시 allowlist만 허용).</p>
   */
  private static void configureCsrf(
      ServerHttpSecurity http, KeycloakSecurityProperties securityProperties) {

    KeycloakCsrfProperties csrfProperties = securityProperties.getCsrf();

    if (!csrfProperties.isEnabled()) {
      http.csrf(ServerHttpSecurity.CsrfSpec::disable);
      log.info("[Configurer] CSRF 비활성화.");
      return;
    }

    List<String> ignorePaths = new ArrayList<>();
    // Back-Channel 로그아웃은 Keycloak 서버→서버 요청이므로 항상 면제 (아래 exemptMatchers에서 POST 한정)

    KeycloakBearerTokenProperties bearerTokenProperties = securityProperties.getBearerToken();
    if (bearerTokenProperties.isEnabled()) {
      String prefix = bearerTokenProperties.getTokenEndpoint().getPrefix();
      // /token, /refresh — 비인증 자격증명 제출 엔드포인트이므로 항상 면제
      ignorePaths.add(prefix + "/token");
      ignorePaths.add(prefix + "/refresh");
      // /logout(prefix) — Bearer Token 전용 로그아웃 API. Bearer 토큰으로만 호출되므로
      // (브라우저 폼 세션과 무관) Bearer Token 활성 시 면제
      ignorePaths.add(prefix + "/logout");
    }

    // 보안 Medium #4: 브라우저 Front-Channel 로그아웃(KeycloakWebFluxConstants.LOGOUT_URL,
    // 기본 "/logout")은 Bearer Token 전용 로그아웃(prefix + "/logout")과 별개의 엔드포인트이며,
    // 항상 CSRF 보호를 유지한다(Bearer Token 활성 여부와 무관). 이 경로는 브라우저 쿠키 기반
    // OIDC 세션을 종료하는 폼 POST 엔드포인트이므로, 여기를 CSRF 면제 목록에 포함시키면 공격
    // 사이트가 크로스사이트 POST로 로그인된 사용자를 강제 로그아웃시킬 수 있다(CSRF, CWE-352).
    // 따라서 어떤 조건에서도 LOGOUT_URL을 ignorePaths에 추가하지 않는다.
    log.debug("[Configurer] /logout(LOGOUT_URL) CSRF 보호 항상 활성화 "
        + "(Bearer Token 활성 여부와 무관, 면제 목록에서 제외)");

    ignorePaths.addAll(csrfProperties.getIgnorePaths());
    log.info("[Configurer] CSRF 활성화 (면제 경로: {}, 토큰 저장소: {})",
        ignorePaths, csrfProperties.getTokenRepository());

    List<ServerWebExchangeMatcher> exemptMatchers = new ArrayList<>();
    for (String path : ignorePaths) {
      exemptMatchers.add(new PathPatternParserServerWebExchangeMatcher(path));
    }

    // M-2: Back-Channel 로그아웃은 POST + exact 경로로 한정
    exemptMatchers.add(new PathPatternParserServerWebExchangeMatcher(
        ReactiveBackChannelLogoutEndpointFilter.BACK_CHANNEL_LOGOUT_PATH, HttpMethod.POST));

    // 보안 Advisory 3: Authorization: Basic 헤더 보유 요청을 CSRF에서 전면 면제하던 로직 제거.
    // 머신 전용 API를 면제하려면 csrfProperties.ignorePaths에 해당 경로를 명시적으로 등록한다.

    ServerWebExchangeMatcher exemptMatcher = new OrServerWebExchangeMatcher(exemptMatchers);

    // 보안 Medium 3: 안전 메서드(GET/HEAD/TRACE/OPTIONS)는 CSRF 기본 동작과 동일하게 항상 제외한다.
    // CsrfWebFilter.DEFAULT_CSRF_MATCHER를 재사용해 Spring Security 표준 안전-메서드 판정을 그대로 따르고,
    // 여기에 "면제 경로가 아님" 조건을 AND로 추가해 최종 보호 대상을 좁힌다.
    // (기존에는 면제 경로 부정만 사용해 안전 메서드까지 CSRF 토큰을 요구 -> GET 등이 403이 되는 버그가 있었다.)
    ServerWebExchangeMatcher csrfMatcher = new AndServerWebExchangeMatcher(
        CsrfWebFilter.DEFAULT_CSRF_MATCHER,
        new NegatedServerWebExchangeMatcher(exemptMatcher)
    );

    // 요구사항 4번: matcher.exclude 경로는 이 체인(CsrfWebFilter 포함) 자체가 적용되지 않아
    // 기본 저장소(SESSION)로는 그 경로에서 CSRF 토큰을 읽거나 심을 수 없다. COOKIE로 전환하면
    // exclude 경로에서도 토큰 쿠키를 읽을 수 있다. 기본값(SESSION)은 null을 반환해
    // csrfTokenRepository(...)를 호출하지 않으므로 Spring Security 기본 동작을 그대로 유지한다.
    ServerCsrfTokenRepository customCsrfTokenRepository =
        resolveCsrfTokenRepository(csrfProperties.getTokenRepository());

    http.csrf(csrf -> {
      csrf.requireCsrfProtectionMatcher(csrfMatcher);
      if (customCsrfTokenRepository != null) {
        csrf.csrfTokenRepository(customCsrfTokenRepository);
      }
    });
  }

  /**
   * {@link CsrfTokenRepositoryMode} 설정값에 해당하는 {@link ServerCsrfTokenRepository}를 생성합니다.
   *
   * @param mode 저장 정책 ({@code null}이면 {@link CsrfTokenRepositoryMode#SESSION}로 처리)
   * @return {@link CsrfTokenRepositoryMode#COOKIE}면 {@code CookieServerCsrfTokenRepository.withHttpOnlyFalse()},
   *     {@link CsrfTokenRepositoryMode#SESSION}(기본값)이면 {@code null}(Spring Security 기본값인
   *     {@code WebSessionServerCsrfTokenRepository} 유지)
   */
  private static ServerCsrfTokenRepository resolveCsrfTokenRepository(CsrfTokenRepositoryMode mode) {
    CsrfTokenRepositoryMode effectiveMode = mode != null ? mode : CsrfTokenRepositoryMode.SESSION;
    if (effectiveMode == CsrfTokenRepositoryMode.COOKIE) {
      return CookieServerCsrfTokenRepository.withHttpOnlyFalse();
    }
    return null;
  }

  /**
   * Ant 패턴 목록을 OR로 결합한 {@link ServerWebExchangeMatcher}로 변환합니다(항목 3).
   */
  private static ServerWebExchangeMatcher toOrMatcher(List<String> patterns) {
    List<ServerWebExchangeMatcher> matchers = new ArrayList<>();
    for (String pattern : patterns) {
      matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern));
    }
    return matchers.size() == 1 ? matchers.get(0) : new OrServerWebExchangeMatcher(matchers);
  }

  /**
   * 인가 설정을 적용합니다.
   */
  private static void configureAuthorization(
      ServerHttpSecurity http,
      KeycloakSecurityProperties securityProperties,
      KeycloakClient keycloakClient) {

    KeycloakAuthorizationProperties authorizationProps = securityProperties.getAuthorization();
    List<String> permitAllPaths = securityProperties.getAuthentication().getPermitAllPaths();

    List<String> allPermitPaths = new ArrayList<>(permitAllPaths);
    if (securityProperties.getBearerToken().isEnabled()) {
      String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
      allPermitPaths.add(prefix + "/token");
      allPermitPaths.add(prefix + "/refresh");
      allPermitPaths.add(prefix + "/logout");
    }
    allPermitPaths.add(KeycloakWebFluxConstants.LOGOUT_URL);

    // C-2: 정적 리소스 permitAll은 명시적 opt-in일 때만 적용한다(KeycloakStaticResourceProperties
    // #permitAll, 기본값 false). 기본값에서는 AuthenticationWebFilter 스킵(성능, configure()의
    // requiresAuthenticationMatcher 참고)만 적용되고 인가는 유지되므로, 이 경로에 컨트롤러로
    // 매핑된 보호 리소스가 있어도 업그레이드만으로 공개되지 않는다.
    KeycloakStaticResourceProperties staticResourceProperties = securityProperties.getStaticResources();
    if (staticResourceProperties.isPermitAllEffective()) {
      allPermitPaths.addAll(staticResourceProperties.getPatterns());
    }

    if (authorizationProps.isEnabled()) {
      KeycloakReactiveAuthorizationManager authorizationManager =
          new KeycloakReactiveAuthorizationManager(keycloakClient);

      http.authorizeExchange(authorize -> {
        if (!allPermitPaths.isEmpty()) {
          String[] paths = allPermitPaths.toArray(new String[0]);
          authorize.pathMatchers(paths).permitAll();
          log.info("[Configurer] 인증 제외 경로 설정: {}", allPermitPaths);
        }
        authorize.anyExchange().access(authorizationManager);
        log.info("[Configurer] Keycloak Authorization Manager 적용 완료.");
      });
    } else {
      http.authorizeExchange(authorize -> {
        if (!allPermitPaths.isEmpty()) {
          String[] paths = allPermitPaths.toArray(new String[0]);
          authorize.pathMatchers(paths).permitAll();
          log.info("[Configurer] 인증 제외 경로 설정: {}", allPermitPaths);
        }
        authorize.anyExchange().authenticated();
      });
    }
  }
}
