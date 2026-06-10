package com.ids.keycloak.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakReactiveAuthenticationManager;
import com.ids.keycloak.security.authentication.ReactiveOidcBackChannelLogoutHandler;
import com.ids.keycloak.security.filter.ReactiveAuthLoggingFilter;
import com.ids.keycloak.security.filter.ReactiveBackChannelLogoutEndpointFilter;
import com.ids.keycloak.security.filter.ReactiveLoggingFilter;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.logging.MdcContextPropagationAccessor;
import com.ids.keycloak.security.ratelimit.InMemoryRateLimiter;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.web.reactive.KeycloakServerAccessDeniedHandler;
import com.ids.keycloak.security.web.reactive.KeycloakServerAuthenticationEntryPoint;
import com.sd.KeycloakClient.config.AbstractKeycloakConfig;
import com.sd.KeycloakClient.config.ClientConfiguration;
import com.sd.KeycloakClient.factory.KeycloakClient;
import io.micrometer.context.ContextRegistry;
import jakarta.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.session.ReactiveFindByIndexNameSessionRepository;

/**
 * Keycloak Spring Security의 WebFlux(Reactive) 환경 자동 설정 진입점입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakServletAutoConfiguration}에 대응합니다.
 * Fail-Open 방지 설계를 동일하게 적용합니다.</p>
 *
 * <p><b>Fail-Open 방지 설계 (CVSS 8.1, CWE-1188/863):</b>
 * <ul>
 *   <li>{@code @ConditionalOnMissingBean(name = "keycloakSecurityWebFilterChain")}으로 Bean 이름 기반 조건</li>
 *   <li>{@code securityMatcher}로 이 체인이 담당할 경로를 명시적으로 선언</li>
 *   <li>{@code @Order(LOWEST_PRECEDENCE)} — catch-all 체인은 가장 낮은 우선순위</li>
 *   <li>{@code keycloak.security.auto-filter-chain=false}로 명시적 opt-out 가능</li>
 * </ul>
 * </p>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
@EnableReactiveMethodSecurity
@Slf4j
public class KeycloakWebFluxAutoConfiguration {

  public KeycloakWebFluxAutoConfiguration() {
    log.info("Keycloak Spring Security: WebFlux(Reactive) 환경 자동 설정이 활성화되었습니다.");
  }

  // ==========================================================================
  // 기반 시설 (Infrastructure)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @Slf4j
  protected static class KeycloakInfrastructureConfiguration {

    @Bean
    @ConditionalOnMissingBean(ObjectMapper.class)
    public ObjectMapper keycloakObjectMapper() {
      log.debug("지원 Bean을 등록합니다: [ObjectMapper]");
      return new ObjectMapper();
    }

    /**
     * KeycloakClient 설정 및 빈 등록.
     */
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

      @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri:#{null}}")
      public String redirectUri;

      @Value("${keycloak.logout.redirect.uri:#{null}}")
      public String logoutRedirectUri;

      @Value("${keycloak.response.type:code}")
      public String responseType;

      @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
      public String clientSecret;

      @Override
      @Bean
      @ConditionalOnMissingBean(KeycloakClient.class)
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

  // ==========================================================================
  // 인증 처리 (Authentication)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @Slf4j
  protected static class KeycloakAuthenticationConfiguration {

    @Bean
    @ConditionalOnMissingBean(ReactiveAuthenticationManager.class)
    public ReactiveAuthenticationManager keycloakReactiveAuthenticationManager(
        KeycloakClient keycloakClient,
        KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig,
        KeycloakSecurityProperties securityProperties) {
      log.info("핵심 Bean을 등록합니다: [ReactiveAuthenticationManager] (KeycloakReactiveAuthenticationManager)");
      KeycloakReactiveAuthenticationManager manager =
          new KeycloakReactiveAuthenticationManager(keycloakClient, keycloakConfig.getClientId());
      // M-2: require-user-info 토글 (기본 false = 기존 동작 유지, 회귀 0)
      manager.setRequireUserInfo(securityProperties.getAuthentication().isRequireUserInfo());
      return manager;
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveSessionManager.class)
    public ReactiveSessionManager reactiveSessionManager() {
      log.debug("지원 Bean을 등록합니다: [ReactiveSessionManager]");
      return new ReactiveSessionManager();
    }
  }

  // ==========================================================================
  // OAuth2 Client 빈 (OIDC 로그인/로그아웃에 필요 — C-1)
  // ==========================================================================

  /**
   * OIDC 로그인 플로우를 지원하기 위한 Reactive OAuth2 Client 협력 빈입니다.
   *
   * <p>Spring Boot가 {@code spring.security.oauth2.client.registration.keycloak.*} 설정으로
   * {@link ReactiveClientRegistrationRepository}를 자동 구성하므로 그대로 활용합니다.
   * 누락된 협력 빈({@link ReactiveOAuth2AuthorizedClientService},
   * {@link ServerOAuth2AuthorizedClientRepository})만 {@code @ConditionalOnMissingBean}으로 보강합니다.</p>
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnBean(ReactiveClientRegistrationRepository.class)
  @Slf4j
  protected static class KeycloakOAuth2ClientConfiguration {

    @Bean
    @ConditionalOnMissingBean(ReactiveOAuth2AuthorizedClientService.class)
    public ReactiveOAuth2AuthorizedClientService reactiveOAuth2AuthorizedClientService(
        ReactiveClientRegistrationRepository clientRegistrationRepository) {
      log.debug("지원 Bean을 등록합니다: [ReactiveOAuth2AuthorizedClientService]");
      return new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    @ConditionalOnMissingBean(ServerOAuth2AuthorizedClientRepository.class)
    public ServerOAuth2AuthorizedClientRepository serverOAuth2AuthorizedClientRepository(
        ReactiveOAuth2AuthorizedClientService authorizedClientService) {
      log.debug("지원 Bean을 등록합니다: [ServerOAuth2AuthorizedClientRepository]");
      return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    /**
     * OIDC authorize 요청 파라미터(acr_values, max_age, prompt)를 커스터마이즈하는
     * {@link ServerOAuth2AuthorizationRequestResolver} 빈을 등록합니다.
     *
     * <p>사용자가 직접 {@link ServerOAuth2AuthorizationRequestResolver} 빈을 등록하면 이 빈은 생략됩니다.
     * {@code keycloak.security.authentication.authorization-request.*} 설정이 모두 null이면
     * customizer가 아무것도 추가하지 않으므로 기존 동작과 완전히 동일합니다(회귀 0).</p>
     */
    @Bean
    @ConditionalOnMissingBean(ServerOAuth2AuthorizationRequestResolver.class)
    public ServerOAuth2AuthorizationRequestResolver keycloakServerAuthorizationRequestResolver(
        ReactiveClientRegistrationRepository clientRegistrationRepository,
        KeycloakSecurityProperties securityProperties) {
      log.debug("지원 Bean을 등록합니다: [ServerOAuth2AuthorizationRequestResolver] "
          + "(Keycloak OIDC authorize 파라미터 커스터마이즈)");
      DefaultServerOAuth2AuthorizationRequestResolver resolver =
          new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);

      resolver.setAuthorizationRequestCustomizer(
          buildAuthorizationRequestCustomizer(
              securityProperties.getAuthentication().getAuthorizationRequest()));

      return resolver;
    }

    /**
     * acr_values, max_age, prompt를 additionalParameters에 주입하는 customizer를 생성합니다.
     *
     * <p>null인 필드는 추가하지 않습니다. 세 필드가 모두 null이면 아무것도 추가하지 않습니다.</p>
     *
     * <p>테스트가 복제 로직 없이 이 메서드를 직접 호출하여 프로덕션 코드를 검증합니다.</p>
     */
    protected static Consumer<OAuth2AuthorizationRequest.Builder>
    buildAuthorizationRequestCustomizer(KeycloakAuthorizationRequestProperties props) {
      return builder -> {
        String acrValues = props.getAcrValues();
        Integer maxAge = props.getMaxAge();
        String prompt = props.getPrompt();

        if (acrValues != null) {
          builder.additionalParameters(p -> p.put("acr_values", acrValues));
        }
        if (maxAge != null) {
          builder.additionalParameters(p -> p.put("max_age", String.valueOf(maxAge)));
        }
        if (prompt != null) {
          builder.additionalParameters(p -> p.put("prompt", prompt));
        }
      };
    }
  }

  // ==========================================================================
  // 로깅 (Logging)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @Slf4j
  protected static class KeycloakLoggingConfiguration {

    /**
     * 기본 PII 마스킹 Sanitizer 등록.
     */
    @Bean
    @ConditionalOnMissingBean(LoggingValueSanitizer.class)
    public LoggingValueSanitizer defaultLoggingValueSanitizer() {
      log.debug("지원 Bean을 등록합니다: [LoggingValueSanitizer] (DefaultPiiMaskingSanitizer)");
      return new DefaultPiiMaskingSanitizer();
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveLoggingFilter.class)
    public ReactiveLoggingFilter reactiveLoggingFilter(
        KeycloakSecurityProperties securityProperties,
        LoggingValueSanitizer sanitizer) {
      log.debug("지원 Bean을 등록합니다: [ReactiveLoggingFilter]");
      return new ReactiveLoggingFilter(securityProperties, sanitizer);
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveAuthLoggingFilter.class)
    public ReactiveAuthLoggingFilter reactiveAuthLoggingFilter(
        KeycloakSecurityProperties securityProperties) {
      log.debug("지원 Bean을 등록합니다: [ReactiveAuthLoggingFilter]");
      return new ReactiveAuthLoggingFilter(securityProperties);
    }
  }

  // ==========================================================================
  // MDC Context Propagation (Reactor Context ↔ MDC 자동 브릿지)
  // ==========================================================================

  /**
   * Micrometer Context Propagation 기반 MDC 자동 브릿지 설정.
   *
   * <p>{@code io.micrometer:context-propagation} 클래스패스에 존재할 때만 활성화됩니다.
   * {@link MdcContextPropagationAccessor}를 {@link ContextRegistry}에 등록하고
   * {@code Hooks.enableAutomaticContextPropagation()}을 1회 활성화합니다.</p>
   *
   * <p><b>전역 Hooks 부작용:</b> M-3에 따라 {@code matchIfMissing=false}로 변경.
   * 사용자가 명시적으로 {@code keycloak.security.logging.mdc-propagation-enabled=true}를 설정해야 합니다.</p>
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "io.micrometer.context.ContextRegistry")
  @ConditionalOnProperty(
      prefix = "keycloak.security.logging",
      name = "mdc-propagation-enabled",
      havingValue = "true",
      matchIfMissing = false)
  @Slf4j
  protected static class KeycloakMdcPropagationConfiguration {

    @PostConstruct
    public void enableMdcPropagation() {
      ContextRegistry.getInstance().registerThreadLocalAccessor(
          new MdcContextPropagationAccessor());
      reactor.core.publisher.Hooks.enableAutomaticContextPropagation();

      log.info("[MDCPropagation] Reactor Context ↔ MDC 자동 브릿지 활성화 완료. "
          + "(MdcContextPropagationAccessor 등록, Hooks.enableAutomaticContextPropagation 설정)");
    }
  }

  // ==========================================================================
  // Back-Channel 로그아웃 (Spring Session Reactive가 활성화된 경우에만)
  // ==========================================================================

  /**
   * Spring Session Reactive({@link ReactiveFindByIndexNameSessionRepository}) 빈이 존재할 때
   * Back-Channel 로그아웃 핸들러와 엔드포인트 필터를 등록합니다.
   *
   * <p>의존성은 compileOnly로 선언되어 있으므로 사용자가 Redis Reactive 등을 사용할 때만 활성화됩니다.
   * H-2: 필터는 전역 WebFilter 빈으로 자동 등록하지 않고, Configurer 내에서 명시 등록합니다.</p>
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "org.springframework.session.ReactiveFindByIndexNameSessionRepository")
  @ConditionalOnBean(type = "org.springframework.session.ReactiveFindByIndexNameSessionRepository")
  @Slf4j
  protected static class KeycloakBackChannelLogoutConfiguration {

    /**
     * Back-Channel logout_token 서명·aud·iss 검증용 {@link ReactiveJwtDecoder}를 등록합니다.
     *
     * <p><b>C-1 aud 검증 추가:</b> {@code ReactiveJwtDecoders.fromIssuerLocation}은 iss·exp·nbf만 검증합니다.
     * audience 미검증 시 같은 Realm의 다른 클라이언트용 logout_token을 수용할 수 있으므로
     * {@link JwtClaimValidator}로 {@code aud} 클레임에 우리 client-id 포함 여부를 추가 검증합니다.
     * {@link DelegatingOAuth2TokenValidator}로 기존 issuer 검증과 결합합니다.</p>
     *
     * <p>사용자가 직접 {@link ReactiveJwtDecoder} 빈을 등록하면 이 빈은 생략됩니다.</p>
     *
     * @param issuerUri  OIDC issuer URI (JWKS 엔드포인트 자동 검색)
     * @param clientId   audience 검증에 사용할 우리 client-id
     */
    @Bean("keycloakBackChannelJwtDecoder")
    @ConditionalOnMissingBean(ReactiveJwtDecoder.class)
    public ReactiveJwtDecoder keycloakBackChannelJwtDecoder(
        @org.springframework.beans.factory.annotation.Value(
            "${spring.security.oauth2.resourceserver.jwt.issuer-uri:"
                + "${spring.security.oauth2.client.provider.keycloak.issuer-uri:}}")
        String issuerUri,
        @org.springframework.beans.factory.annotation.Value(
            "${spring.security.oauth2.client.registration.keycloak.client-id:}")
        String clientId) {
      if (issuerUri == null || issuerUri.isBlank()) {
        throw new IllegalStateException(
            "[C-1] Back-Channel 로그아웃 JWT 서명 검증을 위한 issuer-uri가 설정되지 않았습니다. "
                + "spring.security.oauth2.resourceserver.jwt.issuer-uri 또는 "
                + "spring.security.oauth2.client.provider.keycloak.issuer-uri를 설정하세요.");
      }

      // NimbusReactiveJwtDecoder로 래핑하여 커스텀 validator 조합 가능하게 함
      NimbusReactiveJwtDecoder decoder =
          (NimbusReactiveJwtDecoder) ReactiveJwtDecoders.fromIssuerLocation(issuerUri);

      // issuer 기본 validator + audience validator 결합 (C-1 aud 검증)
      OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuerUri);

      if (clientId != null && !clientId.isBlank()) {
        // logout_token의 aud 클레임에 우리 client-id가 포함되어야 함
        OAuth2TokenValidator<Jwt> audienceValidator =
            new JwtClaimValidator<java.util.List<String>>(
                "aud", aud -> aud != null && aud.contains(clientId));
        decoder.setJwtValidator(
            new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator));
        log.info(
            "핵심 Bean을 등록합니다: [ReactiveJwtDecoder] (Back-Channel 서명+iss+aud 검증, issuer={}, clientId={})",
            issuerUri, clientId);
      } else {
        // client-id 미설정 시 issuer 검증만 (aud 검증 스킵, 경고 출력)
        decoder.setJwtValidator(issuerValidator);
        log.warn(
            "핵심 Bean을 등록합니다: [ReactiveJwtDecoder] (Back-Channel 서명+iss 검증만, aud 미검증 — "
                + "spring.security.oauth2.client.registration.keycloak.client-id 설정 권장)");
      }

      return decoder;
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveOidcBackChannelLogoutHandler.class)
    @SuppressWarnings("unchecked")
    public ReactiveOidcBackChannelLogoutHandler reactiveOidcBackChannelLogoutHandler(
        ReactiveFindByIndexNameSessionRepository<?> sessionRepository,
        ReactiveJwtDecoder jwtDecoder) {
      log.info("핵심 Bean을 등록합니다: [ReactiveOidcBackChannelLogoutHandler] (서명 검증 활성)");
      return new ReactiveOidcBackChannelLogoutHandler(sessionRepository, jwtDecoder);
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveBackChannelLogoutEndpointFilter.class)
    public ReactiveBackChannelLogoutEndpointFilter reactiveBackChannelLogoutEndpointFilter(
        ReactiveOidcBackChannelLogoutHandler logoutHandler) {
      log.info("핵심 Bean을 등록합니다: [ReactiveBackChannelLogoutEndpointFilter]");
      return new ReactiveBackChannelLogoutEndpointFilter(logoutHandler);
    }
  }

  // ==========================================================================
  // Rate Limiting (조건부)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnProperty(
      prefix = "keycloak.security.rate-limit",
      name = "enabled",
      havingValue = "true")
  @Slf4j
  protected static class KeycloakRateLimitConfiguration {

    @Bean
    @ConditionalOnMissingBean(RateLimiter.class)
    public RateLimiter keycloakInMemoryRateLimiter(KeycloakSecurityProperties securityProperties) {
      KeycloakRateLimitProperties props = securityProperties.getRateLimit();
      log.info("지원 Bean을 등록합니다: [RateLimiter] (InMemoryRateLimiter) maxRequests={} window={}s block={}s",
          props.getMaxRequests(), props.getWindowSeconds(), props.getBlockDurationSeconds());
      return new InMemoryRateLimiter(
          props.getMaxRequests(), props.getWindowSeconds(), props.getBlockDurationSeconds());
    }
  }

  // ==========================================================================
  // Bearer Token 컨트롤러 (조건부)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnProperty(
      prefix = "keycloak.security.bearer-token",
      name = "enabled",
      havingValue = "true")
  @Slf4j
  protected static class KeycloakBearerTokenConfiguration {

    @Bean
    @ConditionalOnMissingBean(com.ids.keycloak.security.controller.KeycloakReactiveTokenController.class)
    public com.ids.keycloak.security.controller.KeycloakReactiveTokenController keycloakReactiveTokenController(
        KeycloakClient keycloakClient,
        KeycloakSecurityProperties securityProperties) {
      String prefix = securityProperties.getBearerToken().getTokenEndpoint().getPrefix();
      int trustedProxyCount = securityProperties.getTrustedProxyCount();
      log.info("핵심 Bean을 등록합니다: [KeycloakReactiveTokenController] (prefix={}, trustedProxyCount={})",
          prefix, trustedProxyCount);
      return new com.ids.keycloak.security.controller.KeycloakReactiveTokenController(
          keycloakClient, prefix, trustedProxyCount);
    }
  }

  // ==========================================================================
  // 웹 보안 (Web Security)
  // ==========================================================================

  @Configuration(proxyBeanMethods = false)
  @Slf4j
  protected static class KeycloakWebSecurityConfiguration {

    @Bean
    @ConditionalOnMissingBean(KeycloakServerAuthenticationEntryPoint.class)
    public KeycloakServerAuthenticationEntryPoint keycloakServerAuthenticationEntryPoint(
        ObjectMapper objectMapper,
        KeycloakSecurityProperties securityProperties,
        KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig) {
      log.debug("지원 Bean을 등록합니다: [KeycloakServerAuthenticationEntryPoint]");
      return new KeycloakServerAuthenticationEntryPoint(
          objectMapper,
          securityProperties.getError(),
          securityProperties.getBasicAuth().isEnabled(),
          keycloakConfig.getRealmName());
    }

    @Bean
    @ConditionalOnMissingBean(KeycloakServerAccessDeniedHandler.class)
    public KeycloakServerAccessDeniedHandler keycloakServerAccessDeniedHandler(
        ObjectMapper objectMapper) {
      log.debug("지원 Bean을 등록합니다: [KeycloakServerAccessDeniedHandler]");
      return new KeycloakServerAccessDeniedHandler(objectMapper);
    }

    /**
     * Keycloak 기본 {@link SecurityWebFilterChain}을 등록합니다.
     *
     * <p><b>Fail-Open 방지</b>: Bean 이름 기반 조건 + securityMatcher + {@code @Order(LOWEST_PRECEDENCE)}</p>
     */
    @Bean("keycloakSecurityWebFilterChain")
    @ConditionalOnMissingBean(name = "keycloakSecurityWebFilterChain")
    @ConditionalOnProperty(
        prefix = "keycloak.security",
        name = "auto-filter-chain",
        havingValue = "true",
        matchIfMissing = true)
    @Order(Ordered.LOWEST_PRECEDENCE)
    public SecurityWebFilterChain keycloakSecurityWebFilterChain(
        ServerHttpSecurity http,
        ReactiveAuthenticationManager reactiveAuthenticationManager,
        KeycloakServerAuthenticationEntryPoint entryPoint,
        KeycloakServerAccessDeniedHandler accessDeniedHandler,
        KeycloakSecurityProperties securityProperties,
        KeycloakClient keycloakClient,
        KeycloakInfrastructureConfiguration.KeycloakConfig keycloakConfig,
        ReactiveSessionManager sessionManager,
        org.springframework.beans.factory.ObjectProvider<RateLimiter> rateLimiterProvider,
        org.springframework.beans.factory.ObjectProvider<ReactiveLoggingFilter> loggingFilterProvider,
        org.springframework.beans.factory.ObjectProvider<ReactiveAuthLoggingFilter> authLoggingFilterProvider,
        org.springframework.beans.factory.ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrationRepoProvider,
        org.springframework.beans.factory.ObjectProvider<ReactiveOAuth2AuthorizedClientService> authorizedClientServiceProvider,
        org.springframework.beans.factory.ObjectProvider<ReactiveBackChannelLogoutEndpointFilter> backChannelFilterProvider,
        org.springframework.beans.factory.ObjectProvider<ServerOAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider)
        throws Exception {

      ServerWebExchangeMatcher securityMatcher = buildSecurityMatcher(securityProperties.getMatcher());

      log.info("핵심 Bean을 등록합니다: [SecurityWebFilterChain] (담당 경로 include={}, exclude={})",
          securityProperties.getMatcher().getInclude(),
          securityProperties.getMatcher().getExclude());

      http.securityMatcher(securityMatcher);

      RateLimiter rateLimiter = rateLimiterProvider.getIfAvailable();
      ReactiveLoggingFilter loggingFilter = loggingFilterProvider.getIfAvailable();
      ReactiveAuthLoggingFilter authLoggingFilter = authLoggingFilterProvider.getIfAvailable();
      ReactiveClientRegistrationRepository clientRegistrationRepo =
          clientRegistrationRepoProvider.getIfAvailable();
      ReactiveOAuth2AuthorizedClientService authorizedClientService =
          authorizedClientServiceProvider.getIfAvailable();
      ReactiveBackChannelLogoutEndpointFilter backChannelFilter =
          backChannelFilterProvider.getIfAvailable();
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver =
          authorizationRequestResolverProvider.getIfAvailable();

      return KeycloakWebFluxSecurityConfigurer.configure(
          http,
          reactiveAuthenticationManager,
          entryPoint,
          accessDeniedHandler,
          securityProperties,
          keycloakClient,
          keycloakConfig.getClientId(),
          sessionManager,
          rateLimiter,
          loggingFilter,
          authLoggingFilter,
          clientRegistrationRepo,
          authorizedClientService,
          backChannelFilter,
          authorizationRequestResolver);
    }

    /**
     * include/exclude 패턴을 {@link ServerWebExchangeMatcher}로 변환합니다.
     */
    private ServerWebExchangeMatcher buildSecurityMatcher(KeycloakMatcherProperties properties) {
      List<String> includes = properties.getInclude();
      List<String> excludes = properties.getExclude();

      ServerWebExchangeMatcher includeMatcher = toOrMatcher(includes);

      if (excludes == null || excludes.isEmpty()) {
        return includeMatcher;
      }

      ServerWebExchangeMatcher excludeMatcher = toOrMatcher(excludes);
      return exchange -> includeMatcher.matches(exchange)
          .flatMap(includeResult -> {
            if (!includeResult.isMatch()) {
              return ServerWebExchangeMatcher.MatchResult.notMatch();
            }
            return excludeMatcher.matches(exchange)
                .flatMap(excludeResult ->
                    excludeResult.isMatch()
                        ? ServerWebExchangeMatcher.MatchResult.notMatch()
                        : ServerWebExchangeMatcher.MatchResult.match());
          });
    }

    private ServerWebExchangeMatcher toOrMatcher(List<String> patterns) {
      if (patterns == null || patterns.isEmpty()) {
        return exchange -> ServerWebExchangeMatchers.anyExchange().matches(exchange);
      }
      if (patterns.size() == 1) {
        return new PathPatternParserServerWebExchangeMatcher(patterns.get(0));
      }
      List<ServerWebExchangeMatcher> matchers = new ArrayList<>();
      for (String pattern : patterns) {
        matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern));
      }
      return ServerWebExchangeMatchers.matchers(matchers.toArray(new ServerWebExchangeMatcher[0]));
    }
  }
}
