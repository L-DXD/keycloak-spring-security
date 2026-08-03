package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakLogoutHandler;
import com.ids.keycloak.security.authentication.OidcLoginSuccessHandler;
import com.ids.keycloak.security.exception.KeycloakAccessDeniedHandler;
import com.ids.keycloak.security.exception.KeycloakAuthenticationEntryPoint;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.logging.WebMdcContextAccessor;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

/**
 * {@link KeycloakHttpConfigurer}의 CSRF 설정을 실제로 실행해 검증하는 통합 테스트 (servlet).
 *
 * <p>Spring {@code ApplicationContext}를 부팅하지 않고 {@link HttpSecurity}를 직접 생성한 뒤,
 * production {@link KeycloakHttpConfigurer#init}/{@link KeycloakHttpConfigurer#configure}를
 * {@code KeycloakServletAutoConfiguration#keycloakSecurityFilterChain}과 동일한 순서
 * ({@code http.with(...)} → {@code authorizeHttpRequests} → {@code build()})로 실제 호출한다.
 * 그렇게 만들어진 {@link DefaultSecurityFilterChain}에서 실제 {@link CsrfFilter} 인스턴스를 꺼내
 * 요청을 직접 흘려보내며 검증한다 — matcher/ignore 경로 로직을 테스트에 복제하지 않는다.</p>
 *
 * <p>webflux 모듈의 {@code CsrfExemptMatcherTest}와 동일한 시나리오를 검증해 servlet/webflux
 * 동등성을 확인한다:
 * <ul>
 *   <li><b>보안 Advisory 3:</b> {@code Authorization: Basic} 헤더는 더 이상 CSRF 면제
 *   사유가 아니다.</li>
 *   <li><b>보안 Medium 4:</b> 브라우저 Front-Channel 로그아웃({@code /logout})은 Bearer Token
 *   전용 로그아웃(prefix + {@code /logout})과 별개 엔드포인트이며, Bearer Token 활성 여부와
 *   무관하게 항상 CSRF 보호를 유지해야 한다(CWE-352 — 강제 로그아웃 CSRF 방지).</li>
 * </ul>
 * </p>
 */
class KeycloakHttpConfigurerCsrfTest {

  // ==========================================================================
  // 헬퍼: ApplicationContext를 부팅하지 않고 production init()/configure()를 실제로 호출해
  // DefaultSecurityFilterChain을 빌드하고, 그 안에서 실제 CsrfFilter 인스턴스를 꺼낸다.
  // ==========================================================================

  private KeycloakSecurityProperties baseProperties() {
    KeycloakSecurityProperties props = new KeycloakSecurityProperties();
    props.getCsrf().setEnabled(true);
    props.getBasicAuth().setEnabled(true);
    return props;
  }

  /**
   * "빈 없음" 상태를 나타내는 {@link ObjectProvider}. Mockito 빈 mock과 달리
   * {@code getIfAvailable(Supplier)}/{@code getIfUnique(Supplier)} 같은 fallback 메서드가
   * (인터페이스 default 구현을 통해) 실제로 supplier를 호출하도록 동작한다. Spring Security의
   * 여러 Configurer(OAuth2LoginConfigurer, SecurityContextConfigurer 등)가
   * {@code context.getBeanProvider(X.class).getIfUnique(defaultSupplier)} 패턴으로
   * 선택적 빈을 조회하므로, 이 fallback이 실제로 실행되어야 기본 전략(예: 기본
   * {@code SecurityContextHolderStrategy})으로 정상 대체된다.
   */
  private static <T> ObjectProvider<T> emptyObjectProvider() {
    return new ObjectProvider<>() {
      @Override
      public T getObject() throws BeansException {
        throw new NoSuchBeanDefinitionException(Object.class);
      }

      @Override
      public T getObject(Object... args) throws BeansException {
        throw new NoSuchBeanDefinitionException(Object.class);
      }

      @Override
      public T getIfAvailable() throws BeansException {
        return null;
      }

      @Override
      public T getIfUnique() throws BeansException {
        return null;
      }
    };
  }

  @SuppressWarnings("unchecked")
  private CsrfFilter buildRealCsrfFilter(KeycloakSecurityProperties props) throws Exception {
    KeycloakClient keycloakClient = mock(KeycloakClient.class);
    JwtDecoder jwtDecoder = mock(JwtDecoder.class);

    ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("keycloak")
        .clientId("test-client")
        .clientSecret("test-secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("http://localhost/auth")
        .tokenUri("http://localhost/token")
        .build();
    ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
    when(clientRegistrationRepository.findByRegistrationId("keycloak")).thenReturn(clientRegistration);

    OAuth2AuthorizedClientRepository authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
    KeycloakSessionManager sessionManager = new KeycloakSessionManager();
    OidcLoginSuccessHandler oidcLoginSuccessHandler =
        new OidcLoginSuccessHandler(authorizedClientRepository, sessionManager, "/");
    KeycloakLogoutHandler keycloakLogoutHandler = new KeycloakLogoutHandler(keycloakClient, sessionManager);
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    FindByIndexNameSessionRepository<Session> sessionRepository = mock(FindByIndexNameSessionRepository.class);
    KeycloakAuthenticationEntryPoint entryPoint =
        new KeycloakAuthenticationEntryPoint(new ObjectMapper(), new KeycloakErrorProperties());
    KeycloakAccessDeniedHandler accessDeniedHandler =
        new KeycloakAccessDeniedHandler(new ObjectMapper(), new KeycloakErrorProperties());

    ApplicationContext context = mock(ApplicationContext.class);
    when(context.getBean(KeycloakClient.class)).thenReturn(keycloakClient);
    when(context.getBean(ClientRegistrationRepository.class)).thenReturn(clientRegistrationRepository);
    when(context.getBean(OAuth2AuthorizedClientRepository.class)).thenReturn(authorizedClientRepository);
    when(context.getBean(OidcLoginSuccessHandler.class)).thenReturn(oidcLoginSuccessHandler);
    when(context.getBean(KeycloakLogoutHandler.class)).thenReturn(keycloakLogoutHandler);
    when(context.getBean(OidcClientInitiatedLogoutSuccessHandler.class)).thenReturn(oidcLogoutSuccessHandler);
    when(context.getBean(KeycloakSessionManager.class)).thenReturn(sessionManager);
    when(context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class)).thenReturn(jwtDecoder);
    when(context.getBean(KeycloakSecurityProperties.class)).thenReturn(props);
    when(context.getBean(KeycloakAuthenticationEntryPoint.class)).thenReturn(entryPoint);
    when(context.getBean(KeycloakAccessDeniedHandler.class)).thenReturn(accessDeniedHandler);
    when(context.getBean(LoggingContextAccessor.class)).thenReturn(new WebMdcContextAccessor());
    when(context.getBean(LoggingValueSanitizer.class)).thenReturn(new DefaultPiiMaskingSanitizer());
    // Bearer Token 활성화 시 KeycloakHttpConfigurer#init이 OpaqueTokenIntrospector 빈을 조회한다
    // (bearer-token.enabled=false인 시나리오에서는 조회되지 않으므로 stub만 등록해 두어도 무해하다).
    when(context.getBean(OpaqueTokenIntrospector.class)).thenReturn(mock(OpaqueTokenIntrospector.class));
    // AuthorizeHttpRequestsConfigurer가 MVC 존재 여부/선택적 빈 존재 여부를 확인하기 위해 호출한다
    // (MVC·선택적 빈 미사용 환경으로 취급).
    when(context.getBeanNamesForType(any(Class.class))).thenReturn(new String[0]);
    when(context.getBeanNamesForType(any(ResolvableType.class))).thenReturn(new String[0]);
    // 조회되는 빈이 없을 때 Supplier 기반 fallback(getIfUnique(Supplier) 등)이 실제로 호출되도록,
    // 항상 "빈 없음"으로 동작하는 실제 ObjectProvider 구현체를 반환한다 (빈 mock은 기본값 null만
    // 반환해 fallback Supplier를 호출하지 않으므로 SecurityContextHolderStrategy 등이 null로 남는다).
    when(context.getBeanProvider(any(Class.class))).thenAnswer(invocation -> emptyObjectProvider());
    when(context.getBeanProvider(any(ResolvableType.class))).thenAnswer(invocation -> emptyObjectProvider());

    ObjectPostProcessor<Object> objectPostProcessor = ObjectPostProcessor.identity();
    AuthenticationManagerBuilder authenticationManagerBuilder =
        new AuthenticationManagerBuilder(objectPostProcessor);
    Map<Class<?>, Object> sharedObjects = new HashMap<>();
    sharedObjects.put(ApplicationContext.class, context);

    HttpSecurity http = new HttpSecurity(objectPostProcessor, authenticationManagerBuilder, sharedObjects);

    // 실제 애플리케이션에서는 Spring의 HttpSecurityConfiguration#httpSecurity() 빈 메서드가
    // http 인스턴스를 만들며 exceptionHandling(withDefaults()) 등 기본 Configurer들을 미리
    // 등록해 둔다. KeycloakHttpConfigurer#configure()가 그 시점에 이미 등록된
    // ExceptionHandlingConfigurer를 찾아 재사용(추가 커스터마이즈)하므로, 여기서도 동일하게
    // 기본 등록을 재현한다 (production 로직 복제가 아니라 Spring 표준 기본 배선 재현).
    http.exceptionHandling(Customizer.withDefaults());

    KeycloakHttpConfigurer configurer = KeycloakHttpConfigurer.keycloak().sessionRepository(sessionRepository);

    // production과 동일한 순서: KeycloakServletAutoConfiguration#keycloakSecurityFilterChain 참고
    http.with(configurer, Customizer.withDefaults());
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    DefaultSecurityFilterChain chain = (DefaultSecurityFilterChain) http.build();

    return chain.getFilters().stream()
        .filter(CsrfFilter.class::isInstance)
        .map(CsrfFilter.class::cast)
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("빌드된 체인에 CsrfFilter가 없습니다."));
  }

  /**
   * 실제 {@link CsrfFilter} 인스턴스에 요청을 흘려보내고, 하위 체인까지 도달했는지 여부를 반환한다.
   * CSRF에 막히면 filter가 직접 403을 쓰고 체인 진행을 중단하므로 하위(terminal)에 도달하지 못한다.
   */
  private boolean runThroughRealFilter(CsrfFilter filter, MockHttpServletRequest request,
      MockHttpServletResponse response) throws ServletException, IOException {
    AtomicBoolean reachedDownstream = new AtomicBoolean(false);
    FilterChain terminal = (req, res) -> reachedDownstream.set(true);
    filter.doFilter(request, response, terminal);
    return reachedDownstream.get();
  }

  /**
   * {@code AntPathRequestMatcher}는 {@code servletPath + pathInfo}로 매칭한다.
   * {@link MockHttpServletRequest}는 requestURI만으로는 servletPath를 채우지 않으므로,
   * ignore-paths 매칭을 실제로 검증하려면 servletPath를 명시적으로 맞춰줘야 한다.
   */
  private MockHttpServletRequest newRequest(String method, String path) {
    MockHttpServletRequest request = new MockHttpServletRequest(method, path);
    request.setServletPath(path);
    return request;
  }

  // ==========================================================================
  // 보안 Advisory 3: Authorization: Basic 헤더는 더 이상 CSRF 면제 사유가 아니다 (servlet).
  // webflux CsrfExemptMatcherTest.BasicAuth_헤더는_더이상_CSRF_면제_아님 과 동일 시나리오.
  // ==========================================================================

  @Nested
  class BasicAuth_헤더는_더이상_CSRF_면제_아님 {

    @Test
    void Authorization_Basic_헤더가_있어도_non_ignore_경로는_403() throws Exception {
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/api/resource");
      request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached)
          .as("Basic 헤더 보유만으로 CSRF가 면제되면 안 된다 (Advisory 3)")
          .isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void Authorization_Basic_헤더_브라우저성_cross_site_요청도_403() throws Exception {
      // ambient credential 재전송 시나리오: 브라우저가 캐시한 Basic 자격증명을 실은 채
      // 공격자 origin에서 만든 폼이 자동 제출되는 상황을 흉내낸다.
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/api/resource");
      request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
      request.addHeader("Origin", "https://attacker.example");
      request.setContentType("application/x-www-form-urlencoded");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void Authorization_Basic_헤더가_있어도_ignore_path는_통과() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getCsrf().setIgnorePaths(List.of("/webhook/**"));
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      MockHttpServletRequest request = newRequest("POST", "/webhook/event");
      request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached)
          .as("ignore-paths에 명시적으로 등록된 경로는 여전히 면제되어야 한다")
          .isTrue();
    }

    @Test
    void basicAuth_비활성화여도_CSRF_보호_결과는_동일() throws Exception {
      // Advisory 3 이후로는 basic-auth.enabled 값이 CSRF 판단에 영향을 주지 않는다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBasicAuth().setEnabled(false);
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      MockHttpServletRequest request = newRequest("POST", "/api/resource");
      request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void 일반_경로는_Authorization_헤더가_없어도_토큰_없으면_403() throws Exception {
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/api/submit");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }
  }

  // ==========================================================================
  // 보안 Medium #4: 브라우저 Front-Channel 로그아웃(/logout)은 Bearer Token 활성 여부와
  // 무관하게 항상 CSRF 보호를 유지한다. Bearer Token 전용 로그아웃(prefix + "/logout")과는
  // 별개의 엔드포인트이며, 과거처럼 Bearer 활성 시 /logout까지 면제하면 공격 사이트가
  // 크로스사이트 POST로 로그인 사용자를 강제 로그아웃시킬 수 있다(CWE-352).
  // webflux CsrfExemptMatcherTest.Medium4_브라우저_logout_CSRF_보호_항상_유지 와 동일 시나리오.
  // ==========================================================================

  @Nested
  class Medium4_브라우저_logout_CSRF_보호_항상_유지 {

    @Test
    void bearerToken_비활성시_logout_경로는_CSRF_보호_적용됨() throws Exception {
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/logout");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void bearerToken_활성시에도_logout_경로는_CSRF_보호_유지() throws Exception {
      // 보안 Medium #4 회귀 방지: Bearer Token을 켜도 브라우저 /logout은 면제되면 안 된다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBearerToken().setEnabled(true);
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      MockHttpServletRequest request = newRequest("POST", "/logout");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isFalse();
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void bearerToken_활성시_전용_logout_엔드포인트는_CSRF_면제() throws Exception {
      // Bearer 전용 로그아웃(prefix + "/logout")은 브라우저 폼 세션과 무관하므로 계속 면제된다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBearerToken().setEnabled(true);
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      String prefix = props.getBearerToken().getTokenEndpoint().getPrefix();
      MockHttpServletRequest request = newRequest("POST", prefix + "/logout");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isTrue();
    }

    @Test
    void bearerToken_비활성시_back_channel_경로는_여전히_CSRF_면제() throws Exception {
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/logout/connect/back-channel/keycloak");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached).isTrue();
    }
  }

  // ==========================================================================
  // 항목 4 (f5d82de): keycloak.security.csrf.token-repository — SESSION(기본)/COOKIE.
  // 실제 빌드된 CsrfFilter에 요청을 흘려보내 실제 발급되는 쿠키로 검증한다(로직 복제 금지).
  // ==========================================================================

  @Nested
  class 항목4_CSRF_토큰_저장소_선택 {

    @Test
    void 기본값_SESSION_모드에서는_XSRF_TOKEN_쿠키가_발급되지_않는다() throws Exception {
      CsrfFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockHttpServletRequest request = newRequest("POST", "/api/resource");
      MockHttpServletResponse response = new MockHttpServletResponse();

      runThroughRealFilter(csrfFilter, request, response);

      assertThat(response.getCookie("XSRF-TOKEN"))
          .as("기본값(SESSION)은 csrfTokenRepository(...)를 호출하지 않아 쿠키 저장소로 전환되지 않아야 한다")
          .isNull();
    }

    @Test
    void COOKIE_모드로_전환하면_실제_체인에서_XSRF_TOKEN_쿠키가_httpOnly_false로_발급된다() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getCsrf().setTokenRepository(CsrfTokenRepositoryMode.COOKIE);
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      MockHttpServletRequest request = newRequest("POST", "/api/resource");
      MockHttpServletResponse response = new MockHttpServletResponse();

      runThroughRealFilter(csrfFilter, request, response);

      jakarta.servlet.http.Cookie xsrfCookie = response.getCookie("XSRF-TOKEN");
      assertThat(xsrfCookie)
          .as("COOKIE 모드에서는 matcher.exclude 경로에서도 토큰을 읽을 수 있도록 쿠키로 발급되어야 한다")
          .isNotNull();
      assertThat(xsrfCookie.isHttpOnly())
          .as("CSRF 토큰 쿠키는 JavaScript로 읽어 헤더에 실어야 하므로 httpOnly=false여야 한다")
          .isFalse();
    }

    @Test
    void COOKIE_모드에서도_ignore_path는_여전히_CSRF_면제이다() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getCsrf().setTokenRepository(CsrfTokenRepositoryMode.COOKIE);
      props.getCsrf().setIgnorePaths(List.of("/webhook/**"));
      CsrfFilter csrfFilter = buildRealCsrfFilter(props);

      MockHttpServletRequest request = newRequest("POST", "/webhook/event");
      MockHttpServletResponse response = new MockHttpServletResponse();

      boolean reached = runThroughRealFilter(csrfFilter, request, response);

      assertThat(reached)
          .as("토큰 저장소 선택은 ignore-paths 판단(면제 로직)과 무관해야 한다")
          .isTrue();
    }
  }
}
