package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.ReactiveCookieUtil;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * OidcReactiveLoginSuccessHandler 단위 테스트.
 * - Access Token 쿠키 발급 검증
 * - ID Token 쿠키 발급 검증
 * - Refresh Token 세션 저장 검증
 * - Keycloak SID 세션 저장 검증
 * - OAuth2AuthenticationToken 이 아닌 경우 기본 리다이렉트 검증
 */
class OidcReactiveLoginSuccessHandlerTest {

  private ReactiveOAuth2AuthorizedClientService authorizedClientService;
  private ReactiveSessionManager sessionManager;
  private KeycloakCookieProperties cookieProperties;
  private OidcReactiveLoginSuccessHandler handler;

  @BeforeEach
  void setUp() {
    authorizedClientService = mock(ReactiveOAuth2AuthorizedClientService.class);
    sessionManager = mock(ReactiveSessionManager.class);
    cookieProperties = new KeycloakCookieProperties();
    handler = new OidcReactiveLoginSuccessHandler(
        authorizedClientService, sessionManager, cookieProperties, "/home");
  }

  // =========================================================
  // 정상 플로우: OIDC 로그인 성공 + AuthorizedClient 존재
  // =========================================================
  @Nested
  @DisplayName("정상 플로우 - AuthorizedClient 존재")
  class 정상_플로우 {

    @Test
    @DisplayName("access_token / id_token 쿠키가 응답에 추가된다")
    void 토큰_쿠키_발급() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      // Access Token 쿠키 확인
      boolean hasAccessToken = exchange.getResponse().getCookies().values().stream()
          .flatMap(List::stream)
          .anyMatch(c -> c.getName().equals(ReactiveCookieUtil.ACCESS_TOKEN_NAME)
              && "access-tok".equals(c.getValue()));
      assertThat(hasAccessToken).isTrue();

      // ID Token 쿠키 확인
      boolean hasIdToken = exchange.getResponse().getCookies().values().stream()
          .flatMap(List::stream)
          .anyMatch(c -> c.getName().equals(ReactiveCookieUtil.ID_TOKEN_NAME)
              && "id-token-value".equals(c.getValue()));
      assertThat(hasIdToken).isTrue();
    }

    @Test
    @DisplayName("Refresh Token이 세션에 저장된다")
    void 리프레시_토큰_세션_저장() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      verify(sessionManager, times(1)).saveRefreshToken(any(), anyString());
    }

    @Test
    @DisplayName("Keycloak SID가 세션에 저장된다")
    void 세션_ID_저장() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      verify(sessionManager, times(1)).saveKeycloakSessionId(any(), anyString());
    }

    @Test
    @DisplayName("Principal Name이 세션에 저장된다")
    void 프린시팔_이름_저장() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      verify(sessionManager, times(1)).savePrincipalName(any(), anyString());
    }

    @Test
    @DisplayName("성공 후 /home 으로 리다이렉트된다")
    void 리다이렉트() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/other").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
      URI location = exchange.getResponse().getHeaders().getLocation();
      assertThat(location).isNotNull();
      assertThat(location.getPath()).isEqualTo("/home");
    }
  }

  // =========================================================
  // 보안 Advisory 2: 세션 고정 보호 — 인증 상태 저장 전 세션 ID 회전
  // =========================================================
  @Nested
  @DisplayName("보안 Advisory 2 - 세션 고정 보호")
  class 세션_고정_보호 {

    @Test
    @DisplayName("AuthorizedClient 존재 경로: 로그인 성공 시 세션 ID가 회전되고, 회전된 세션 ID에 인증 상태가 저장된다")
    void authorizedClient_존재시_세션ID_회전후_저장() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      // 인증 전(예: OAuth2 authorization request 처리 중 생성된) 세션 ID 확보
      String preLoginSessionId = exchange.getSession().block().getId();

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      String postLoginSessionId = exchange.getSession().block().getId();

      // 세션 ID가 로그인 전후로 달라야 한다 (세션 고정 보호)
      assertThat(postLoginSessionId).isNotEqualTo(preLoginSessionId);

      // Refresh Token/Principal Name/sid는 회전된(새) 세션 ID에 정확히 1회만 저장되어야 한다.
      // (dual-path 버그 수정 전에는 switchIfEmpty(...)가 Mono<Void> 소스를 "empty"로 간주해
      // issueIdTokenCookieOnly 경로가 함께 실행되어 2회 저장되는 문제가 있었음 — 수정 후 1회로 고정된다.)
      ArgumentCaptor<WebSession> refreshSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, times(1)).saveRefreshToken(refreshSessionCaptor.capture(), anyString());
      assertThat(refreshSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);

      ArgumentCaptor<WebSession> principalSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, times(1)).savePrincipalName(principalSessionCaptor.capture(), anyString());
      assertThat(principalSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);

      ArgumentCaptor<WebSession> sidSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, times(1)).saveKeycloakSessionId(sidSessionCaptor.capture(), anyString());
      assertThat(sidSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);
    }

    @Test
    @DisplayName("AuthorizedClient 없는(ID Token만 있는) 경로도 로그인 성공 시 세션 ID가 회전된다")
    void authorizedClient_없을때도_세션ID_회전() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "sid-xyz");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.empty());

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      String preLoginSessionId = exchange.getSession().block().getId();

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      String postLoginSessionId = exchange.getSession().block().getId();

      assertThat(postLoginSessionId).isNotEqualTo(preLoginSessionId);

      ArgumentCaptor<WebSession> principalSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager).savePrincipalName(principalSessionCaptor.capture(), anyString());
      assertThat(principalSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);
    }
  }

  // =========================================================
  // Dual-path 버그 회귀 방지: 로그인당 정확히 단일 경로만 실행되어야 한다.
  // (issueTokenCookiesAndSaveSession XOR issueIdTokenCookieOnly, changeSessionId는 정확히 1회)
  // =========================================================
  @Nested
  @DisplayName("단일 경로 실행 보장 - dual-path 버그 회귀 방지")
  class 단일_경로_실행_보장 {

    @Test
    @DisplayName("AuthorizedClient 존재 시 토큰쿠키 경로만 실행되고, changeSessionId는 정확히 1회만 호출된다")
    void authorizedClient_존재시_토큰쿠키경로_단일실행() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "session-sid-abc");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);
      OAuth2AuthorizedClient authorizedClient = mockAuthorizedClient("access-tok", "refresh-tok");

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.just(authorizedClient));

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      SessionSpySetup spySetup = wrapWithSessionSpy(exchange);

      StepVerifier.create(handler.onAuthenticationSuccess(spySetup.webFilterExchange(), authentication))
          .verifyComplete();

      // 세션 ID 회전은 로그인당 정확히 1회만 발생해야 한다 (dual-path 버그 시 2회 호출됨).
      verify(spySetup.sessionSpy(), times(1)).changeSessionId();

      // access_token / id_token 쿠키는 각각 정확히 1개만 발급되어야 한다 (Set-Cookie 중복 없음).
      assertThat(exchange.getResponse().getCookies().get(ReactiveCookieUtil.ACCESS_TOKEN_NAME))
          .hasSize(1);
      assertThat(exchange.getResponse().getCookies().get(ReactiveCookieUtil.ID_TOKEN_NAME))
          .hasSize(1);

      // issueTokenCookiesAndSaveSession 경로만 실행되었음을 사이드이펙트로 확인:
      // Refresh Token 저장은 이 경로에서만 발생하므로 정확히 1회 호출되어야 한다.
      verify(sessionManager, times(1)).saveRefreshToken(any(), anyString());
      // 두 경로 공통 저장 로직도 dual-path 버그였다면 2회 호출됐을 것 — 정확히 1회여야 단일 경로 실행 증명.
      verify(sessionManager, times(1)).savePrincipalName(any(), anyString());
      verify(sessionManager, times(1)).saveKeycloakSessionId(any(), anyString());
    }

    @Test
    @DisplayName("AuthorizedClient가 없을 때 ID Token 전용 경로만 실행되고, changeSessionId는 정확히 1회만 호출된다")
    void authorizedClient_없을때_ID토큰전용경로_단일실행() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "sid-xyz");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.empty());

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      SessionSpySetup spySetup = wrapWithSessionSpy(exchange);

      StepVerifier.create(handler.onAuthenticationSuccess(spySetup.webFilterExchange(), authentication))
          .verifyComplete();

      verify(spySetup.sessionSpy(), times(1)).changeSessionId();

      // access_token 쿠키는 AuthorizedClient가 없으므로 발급되지 않아야 한다
      // (issueTokenCookiesAndSaveSession 경로가 실행되지 않았음을 증명).
      assertThat(exchange.getResponse().getCookies().get(ReactiveCookieUtil.ACCESS_TOKEN_NAME))
          .isNullOrEmpty();
      assertThat(exchange.getResponse().getCookies().get(ReactiveCookieUtil.ID_TOKEN_NAME))
          .hasSize(1);

      // issueTokenCookiesAndSaveSession 경로가 실행되지 않았음을 사이드이펙트로 확인:
      // Refresh Token 저장은 그 경로에만 존재하므로 전혀 호출되지 않아야 한다.
      verify(sessionManager, never()).saveRefreshToken(any(), anyString());
      verify(sessionManager, times(1)).savePrincipalName(any(), anyString());
      verify(sessionManager, times(1)).saveKeycloakSessionId(any(), anyString());
    }
  }

  // =========================================================
  // 엣지 케이스: OAuth2AuthenticationToken이 아닌 경우
  // =========================================================
  @Nested
  @DisplayName("엣지 케이스")
  class 엣지_케이스 {

    @Test
    @DisplayName("일반 Authentication이면 쿠키 없이 기본 리다이렉트만 수행")
    void 비_OAuth2_인증_기본_리다이렉트() {
      var nonOAuth2 = mock(org.springframework.security.core.Authentication.class);
      when(nonOAuth2.getName()).thenReturn("user");
      when(nonOAuth2.isAuthenticated()).thenReturn(true);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, nonOAuth2))
          .verifyComplete();

      // 쿠키 없음
      assertThat(exchange.getResponse().getCookies().isEmpty()).isTrue();
    }

    @Test
    @DisplayName("AuthorizedClient가 없어도 ID Token 쿠키는 발급된다")
    void AuthorizedClient_없을_때_ID_Token만_발급() {
      OidcUser oidcUser = mockOidcUser("user-sub-123", "sid-xyz");
      OAuth2AuthenticationToken authentication = mockOAuth2Token(oidcUser);

      when(authorizedClientService.loadAuthorizedClient(anyString(), anyString()))
          .thenReturn(Mono.empty());

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/home").build());
      WebFilterExchange wfe = new WebFilterExchange(exchange, chain -> Mono.empty());

      StepVerifier.create(handler.onAuthenticationSuccess(wfe, authentication))
          .verifyComplete();

      boolean hasIdToken = exchange.getResponse().getCookies().values().stream()
          .flatMap(List::stream)
          .anyMatch(c -> c.getName().equals(ReactiveCookieUtil.ID_TOKEN_NAME));
      assertThat(hasIdToken).isTrue();
    }
  }

  // =========================================================
  // 헬퍼 메서드
  // =========================================================

  /**
   * 실제(real) WebSession을 스파이로 감싸 {@code changeSessionId()} 등의 호출 횟수를 검증할 수 있도록
   * ServerWebExchange를 데코레이팅한다. 응답/쿠키 검증은 원본 {@code exchange}로 그대로 수행하면 된다.
   *
   * <p>{@code InMemoryWebSessionStore}의 세션 구현은 세션 ID를 {@code AtomicReference}로 보관하는데,
   * Mockito {@code spy()}는 원본 인스턴스의 필드를 얕은 복사하므로 스파이와 원본이 동일한
   * {@code AtomicReference} 인스턴스를 공유한다. 따라서 스파이의 {@code changeSessionId()} 호출로
   * 발생한 세션 ID 변경이 원본 {@code exchange.getSession()} 결과에도 그대로 반영된다.
   */
  private SessionSpySetup wrapWithSessionSpy(MockServerWebExchange exchange) {
    WebSession realSession = exchange.getSession().block();
    WebSession sessionSpy = spy(realSession);
    ServerWebExchange decoratedExchange = new ServerWebExchangeDecorator(exchange) {
      @Override
      public Mono<WebSession> getSession() {
        return Mono.just(sessionSpy);
      }
    };
    WebFilterExchange wfe = new WebFilterExchange(decoratedExchange, chain -> Mono.empty());
    return new SessionSpySetup(wfe, sessionSpy);
  }

  private record SessionSpySetup(WebFilterExchange webFilterExchange, WebSession sessionSpy) {}

  private OidcUser mockOidcUser(String subject, String sid) {
    OidcIdToken idToken = new OidcIdToken(
        "id-token-value",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("sub", subject, "sid", sid));
    OidcUserInfo userInfo = new OidcUserInfo(Map.of(
        "sub", subject,
        "preferred_username", "testuser"));

    OidcUser oidcUser = mock(OidcUser.class);
    when(oidcUser.getName()).thenReturn(subject);
    when(oidcUser.getIdToken()).thenReturn(idToken);
    when(oidcUser.getUserInfo()).thenReturn(userInfo);
    when(oidcUser.getAuthorities()).thenReturn(List.of());
    when(oidcUser.getAttributes()).thenReturn(Map.of("sub", subject));
    return oidcUser;
  }

  private OAuth2AuthenticationToken mockOAuth2Token(OidcUser oidcUser) {
    return new OAuth2AuthenticationToken(oidcUser, List.of(), "keycloak");
  }

  private OAuth2AuthorizedClient mockAuthorizedClient(
      String accessTokenValue, String refreshTokenValue) {
    OAuth2AccessToken accessToken = new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        accessTokenValue,
        Instant.now(),
        Instant.now().plusSeconds(3600));
    OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
        refreshTokenValue, Instant.now());

    OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
    when(client.getAccessToken()).thenReturn(accessToken);
    when(client.getRefreshToken()).thenReturn(refreshToken);
    return client;
  }
}
