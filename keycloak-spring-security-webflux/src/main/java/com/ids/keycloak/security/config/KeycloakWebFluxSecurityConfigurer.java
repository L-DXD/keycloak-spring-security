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
      http.addFilterBefore(rateLimitFilter, SecurityWebFiltersOrder.HTTP_BASIC);
      log.info("[Configurer] Rate Limit 필터 등록 완료 (대상 경로: {}, Basic 포함: {})",
          rateLimitPaths, rateLimitProps.isIncludeBasicAuth());
    }

    // 6. Basic Auth 필터 등록 (조건부)
    if (securityProperties.getBasicAuth().isEnabled()) {
      ReactiveBasicAuthenticationFilter basicAuthFilter =
          new ReactiveBasicAuthenticationFilter(keycloakClient, clientId);
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

    AuthenticationWebFilter authFilter = new AuthenticationWebFilter(authenticationManager);
    authFilter.setServerAuthenticationConverter(converter);
    http.addFilterAt(authFilter, SecurityWebFiltersOrder.AUTHENTICATION);
    log.debug("[Configurer] AuthenticationWebFilter (OIDC Cookie) 등록 완료.");

    // 8. CSRF 설정
    configureCsrf(http, securityProperties);

    // 9. Bearer Token Resource Server 설정 (조건부)
    if (securityProperties.getBearerToken().isEnabled()) {
      KeycloakReactiveOpaqueTokenIntrospector introspector =
          new KeycloakReactiveOpaqueTokenIntrospector(keycloakClient, clientId);
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
   * <p>API 서버 기본값은 disabled. CSRF 활성화 시 면제 경로를 {@code requireCsrfProtectionMatcher}에
   * <b>부정 매처(NegatedServerWebExchangeMatcher)</b>로 지정합니다.</p>
   *
   * <p><b>면제 대상:</b>
   * <ul>
   *   <li>Front-Channel 로그아웃 경로 ({@code /logout})</li>
   *   <li>Back-Channel 로그아웃 경로 — POST+exact 경로 한정 (M-2 보강)</li>
   *   <li>Bearer Token 엔드포인트 경로</li>
   *   <li>사용자 지정 ignorePaths</li>
   *   <li>Basic Auth 활성화 시 {@code Authorization: Basic} 헤더 보유 요청</li>
   * </ul>
   * </p>
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
    ignorePaths.add(KeycloakWebFluxConstants.LOGOUT_URL);

    if (securityProperties.getBearerToken().isEnabled()) {
      String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
      ignorePaths.add(prefix + "/token");
      ignorePaths.add(prefix + "/refresh");
      ignorePaths.add(prefix + "/logout");
    }

    ignorePaths.addAll(csrfProperties.getIgnorePaths());
    log.info("[Configurer] CSRF 활성화 (면제 경로: {})", ignorePaths);

    List<ServerWebExchangeMatcher> exemptMatchers = new ArrayList<>();
    for (String path : ignorePaths) {
      exemptMatchers.add(new PathPatternParserServerWebExchangeMatcher(path));
    }

    // M-2: Back-Channel 로그아웃은 POST + exact 경로로 한정
    exemptMatchers.add(new PathPatternParserServerWebExchangeMatcher(
        ReactiveBackChannelLogoutEndpointFilter.BACK_CHANNEL_LOGOUT_PATH, HttpMethod.POST));

    if (securityProperties.getBasicAuth().isEnabled()) {
      ServerWebExchangeMatcher basicAuthMatcher =
          exchange -> {
            String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (auth != null && auth.startsWith("Basic ")) {
              return ServerWebExchangeMatcher.MatchResult.match();
            }
            return ServerWebExchangeMatcher.MatchResult.notMatch();
          };
      exemptMatchers.add(basicAuthMatcher);
    }

    ServerWebExchangeMatcher exemptMatcher = new OrServerWebExchangeMatcher(exemptMatchers);
    ServerWebExchangeMatcher csrfMatcher = new NegatedServerWebExchangeMatcher(exemptMatcher);

    http.csrf(csrf -> csrf.requireCsrfProtectionMatcher(csrfMatcher));
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
