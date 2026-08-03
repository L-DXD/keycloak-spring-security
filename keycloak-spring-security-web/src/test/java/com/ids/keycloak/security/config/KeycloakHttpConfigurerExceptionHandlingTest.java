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
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 회귀 테스트: {@code keycloak.security.error.*}가 실제로 필터체인에 적용되는지 검증한다.
 *
 * <p>버그 배경: {@link KeycloakHttpConfigurer#configure} 에서 {@code http.exceptionHandling(...)}을
 * 호출했었는데, {@code oauth2Login}이 {@code ExceptionHandlingConfigurer}의
 * {@code defaultEntryPointMappings}에 심어둔 로그인 페이지 리다이렉트 EntryPoint가
 * ({@code ExceptionHandlingConfigurer#configure()}가 더 먼저 실행되는 등록 순서상) 먼저 확정되어,
 * 우리가 나중에 지정한 {@link KeycloakAuthenticationEntryPoint}/{@link KeycloakAccessDeniedHandler}가
 * {@link ExceptionTranslationFilter}에 반영되지 않았다(대신 {@code DelegatingAuthenticationEntryPoint}가
 * 확정됨). 수정: 설정을 {@code init()}으로 이동(필드가 non-null이면 default 매핑을 무시하는
 * {@code ExceptionHandlingConfigurer#getAuthenticationEntryPoint(H)}/{@code #getAccessDeniedHandler(H)}
 * 규칙을 이용).</p>
 *
 * <p>{@link KeycloakHttpConfigurerCsrfTest}와 동일하게, {@code ApplicationContext}를 부팅하지 않고
 * production {@code init()}/{@code configure()}를 {@code KeycloakServletAutoConfiguration}과 동일한
 * 순서로 실제 호출해 {@link DefaultSecurityFilterChain}을 빌드한 뒤, 그 안에서 실제
 * {@link ExceptionTranslationFilter} 인스턴스를 꺼내 검증한다 — 로직을 테스트에 복제하지 않는다.</p>
 */
class KeycloakHttpConfigurerExceptionHandlingTest {

  private KeycloakSecurityProperties baseProperties() {
    KeycloakSecurityProperties props = new KeycloakSecurityProperties();
    props.getCsrf().setEnabled(true);
    props.getBasicAuth().setEnabled(true);
    return props;
  }

  /**
   * {@link KeycloakHttpConfigurerCsrfTest#emptyObjectProvider()}와 동일한 목적: "빈 없음" 상태를
   * 나타내는 실제 {@link ObjectProvider} 구현체. Mockito 빈 mock과 달리 fallback 메서드가 실제로
   * supplier를 호출하도록 동작한다.
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

  /**
   * production {@link KeycloakHttpConfigurer#init}/{@link KeycloakHttpConfigurer#configure}를 실제로
   * 호출해 {@link DefaultSecurityFilterChain}을 빌드한다. {@code errorProperties}로 등록될
   * {@link KeycloakAuthenticationEntryPoint}/{@link KeycloakAccessDeniedHandler}의 동작을 제어한다.
   */
  @SuppressWarnings("unchecked")
  private DefaultSecurityFilterChain buildChain(KeycloakSecurityProperties props, KeycloakErrorProperties errorProperties)
      throws Exception {
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
    // 수정 전이라면 이 인스턴스가 아니라 oauth2Login이 심은 DelegatingAuthenticationEntryPoint가
    // ExceptionTranslationFilter에 확정되어 있었다.
    KeycloakAuthenticationEntryPoint entryPoint =
        new KeycloakAuthenticationEntryPoint(new ObjectMapper(), errorProperties);
    KeycloakAccessDeniedHandler accessDeniedHandler =
        new KeycloakAccessDeniedHandler(new ObjectMapper(), errorProperties);

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
    when(context.getBean(OpaqueTokenIntrospector.class)).thenReturn(mock(OpaqueTokenIntrospector.class));
    when(context.getBeanNamesForType(any(Class.class))).thenReturn(new String[0]);
    when(context.getBeanNamesForType(any(ResolvableType.class))).thenReturn(new String[0]);
    when(context.getBeanProvider(any(Class.class))).thenAnswer(invocation -> emptyObjectProvider());
    when(context.getBeanProvider(any(ResolvableType.class))).thenAnswer(invocation -> emptyObjectProvider());

    ObjectPostProcessor<Object> objectPostProcessor = ObjectPostProcessor.identity();
    AuthenticationManagerBuilder authenticationManagerBuilder =
        new AuthenticationManagerBuilder(objectPostProcessor);
    Map<Class<?>, Object> sharedObjects = new HashMap<>();
    sharedObjects.put(ApplicationContext.class, context);

    HttpSecurity http = new HttpSecurity(objectPostProcessor, authenticationManagerBuilder, sharedObjects);

    // Spring Boot의 HttpSecurityConfiguration#httpSecurity()가 exceptionHandling(withDefaults())로
    // ExceptionHandlingConfigurer를 미리 등록해 두는 것을 재현한다 (production 로직 복제가 아니라
    // Spring 표준 기본 배선 재현). oauth2Login이 여기에 defaultEntryPointMappings를 심는다.
    http.exceptionHandling(Customizer.withDefaults());

    KeycloakHttpConfigurer configurer = KeycloakHttpConfigurer.keycloak().sessionRepository(sessionRepository);

    // production과 동일한 순서: KeycloakServletAutoConfiguration#keycloakSecurityFilterChain 참고
    http.with(configurer, Customizer.withDefaults());
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    return (DefaultSecurityFilterChain) http.build();
  }

  private ExceptionTranslationFilter extractExceptionTranslationFilter(DefaultSecurityFilterChain chain) {
    return chain.getFilters().stream()
        .filter(ExceptionTranslationFilter.class::isInstance)
        .map(ExceptionTranslationFilter.class::cast)
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("빌드된 체인에 ExceptionTranslationFilter가 없습니다."));
  }

  // ==========================================================================
  // 핵심 회귀 검증: 필터체인에 실제로 확정된 EntryPoint/AccessDeniedHandler가 Keycloak 것인지 확인.
  // 수정 전이라면 authenticationEntryPoint는 oauth2Login이 defaultEntryPointMappings에 심은
  // DelegatingAuthenticationEntryPoint였다.
  // ==========================================================================

  @Nested
  class ExceptionTranslationFilter_에_Keycloak_핸들러가_확정된다 {

    @Test
    void oauth2Login_활성_상태에서도_authenticationEntryPoint는_KeycloakAuthenticationEntryPoint이다() throws Exception {
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), new KeycloakErrorProperties());

      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AuthenticationEntryPoint appliedEntryPoint =
          (AuthenticationEntryPoint) ReflectionTestUtils.getField(filter, "authenticationEntryPoint");

      assertThat(appliedEntryPoint)
          .as("oauth2Login이 심은 DelegatingAuthenticationEntryPoint가 아니라 우리가 지정한 EntryPoint여야 한다")
          .isInstanceOf(KeycloakAuthenticationEntryPoint.class);
    }

    @Test
    void oauth2Login_활성_상태에서도_accessDeniedHandler는_KeycloakAccessDeniedHandler이다() throws Exception {
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), new KeycloakErrorProperties());

      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AccessDeniedHandler appliedHandler =
          (AccessDeniedHandler) ReflectionTestUtils.getField(filter, "accessDeniedHandler");

      assertThat(appliedHandler).isInstanceOf(KeycloakAccessDeniedHandler.class);
    }
  }

  // ==========================================================================
  // 동작 검증: 필터체인에 실제로 확정된(=extractExceptionTranslationFilter로 꺼낸) EntryPoint/
  // AccessDeniedHandler 인스턴스를 그대로 사용해, keycloak.security.error.* 프로퍼티가 실제로
  // 반영되는지 확인한다.
  // ==========================================================================

  @Nested
  class 확정된_핸들러의_동작이_error_프로퍼티를_반영한다 {

    @Test
    void 기본_설정_API_모드에서_미인증_요청은_401_JSON을_반환한다() throws Exception {
      // redirect-enabled 기본값 false → API 모드: AJAX 여부와 무관하게 항상 401 JSON
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), new KeycloakErrorProperties());
      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AuthenticationEntryPoint appliedEntryPoint =
          (AuthenticationEntryPoint) ReflectionTestUtils.getField(filter, "authenticationEntryPoint");

      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");
      MockHttpServletResponse response = new MockHttpServletResponse();
      AuthenticationException authException = new InsufficientAuthenticationException("인증 필요");

      appliedEntryPoint.commence(request, response, authException);

      assertThat(response.getStatus()).isEqualTo(401);
      assertThat(response.getContentType()).contains("application/json");
      assertThat(response.getContentAsString()).contains("AUTHENTICATION_FAILED");
    }

    @Test
    void ajax_returns_json_활성시_XHR_요청은_401_JSON을_반환한다() throws Exception {
      KeycloakErrorProperties errorProperties = new KeycloakErrorProperties();
      errorProperties.setRedirectEnabled(true);
      errorProperties.setAjaxReturnsJson(true);
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), errorProperties);
      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AuthenticationEntryPoint appliedEntryPoint =
          (AuthenticationEntryPoint) ReflectionTestUtils.getField(filter, "authenticationEntryPoint");

      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");
      request.addHeader("X-Requested-With", "XMLHttpRequest");
      MockHttpServletResponse response = new MockHttpServletResponse();
      AuthenticationException authException = new InsufficientAuthenticationException("인증 필요");

      appliedEntryPoint.commence(request, response, authException);

      assertThat(response.getStatus()).isEqualTo(401);
      assertThat(response.getContentType()).contains("application/json");
      assertThat(response.getContentAsString()).contains("AUTHENTICATION_FAILED");
    }

    @Test
    void ajax_returns_json_활성시_일반_요청은_로그인_페이지로_리다이렉트한다() throws Exception {
      KeycloakErrorProperties errorProperties = new KeycloakErrorProperties();
      errorProperties.setRedirectEnabled(true);
      errorProperties.setAjaxReturnsJson(true);
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), errorProperties);
      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AuthenticationEntryPoint appliedEntryPoint =
          (AuthenticationEntryPoint) ReflectionTestUtils.getField(filter, "authenticationEntryPoint");

      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/page");
      MockHttpServletResponse response = new MockHttpServletResponse();
      AuthenticationException authException = new InsufficientAuthenticationException("인증 필요");

      appliedEntryPoint.commence(request, response, authException);

      assertThat(response.getStatus()).isEqualTo(302);
      assertThat(response.getRedirectedUrl()).isEqualTo(errorProperties.getAuthenticationFailedRedirectUrl());
    }

    @Test
    void 기본_설정_API_모드에서_인가_실패_요청은_403_JSON을_반환한다() throws Exception {
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), new KeycloakErrorProperties());
      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AccessDeniedHandler appliedHandler =
          (AccessDeniedHandler) ReflectionTestUtils.getField(filter, "accessDeniedHandler");

      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");
      MockHttpServletResponse response = new MockHttpServletResponse();

      appliedHandler.handle(request, response, new AccessDeniedException("권한 없음"));

      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.getContentType()).contains("application/json");
      assertThat(response.getContentAsString()).contains("ACCESS_DENIED");
    }

    @Test
    void redirect_활성시_인가_실패_요청은_403_페이지로_리다이렉트한다() throws Exception {
      KeycloakErrorProperties errorProperties = new KeycloakErrorProperties();
      errorProperties.setRedirectEnabled(true);
      DefaultSecurityFilterChain chain = buildChain(baseProperties(), errorProperties);
      ExceptionTranslationFilter filter = extractExceptionTranslationFilter(chain);
      AccessDeniedHandler appliedHandler =
          (AccessDeniedHandler) ReflectionTestUtils.getField(filter, "accessDeniedHandler");

      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/page");
      MockHttpServletResponse response = new MockHttpServletResponse();

      appliedHandler.handle(request, response, new AccessDeniedException("권한 없음"));

      assertThat(response.getStatus()).isEqualTo(302);
      assertThat(response.getRedirectedUrl()).isEqualTo(errorProperties.getAccessDeniedRedirectUrl());
    }
  }
}
