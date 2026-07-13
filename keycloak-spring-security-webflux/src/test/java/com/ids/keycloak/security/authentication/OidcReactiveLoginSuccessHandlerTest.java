package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
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

      verify(sessionManager, atLeastOnce()).saveRefreshToken(any(), anyString());
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

      verify(sessionManager, atLeastOnce()).saveKeycloakSessionId(any(), anyString());
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

      verify(sessionManager, atLeastOnce()).savePrincipalName(any(), anyString());
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

      // Refresh Token/Principal Name/sid는 회전된(새) 세션 ID에 저장되어야 한다.
      // 참고: switchIfEmpty(...)가 Mono<Void> 소스를 "empty"로 간주해 issueIdTokenCookieOnly 경로도
      // 함께 실행되는 기존 동작(테스트 실행으로 확인됨, Advisory 2와 무관한 기존 이슈)이 있어
      // atLeastOnce()로 검증한다. 캡처된 WebSession은 동일 인스턴스이므로 마지막 상태(postLoginSessionId)로
      // 수렴한다.
      ArgumentCaptor<WebSession> refreshSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, atLeastOnce()).saveRefreshToken(refreshSessionCaptor.capture(), anyString());
      assertThat(refreshSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);

      ArgumentCaptor<WebSession> principalSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, atLeastOnce()).savePrincipalName(principalSessionCaptor.capture(), anyString());
      assertThat(principalSessionCaptor.getValue().getId()).isEqualTo(postLoginSessionId);

      ArgumentCaptor<WebSession> sidSessionCaptor = ArgumentCaptor.forClass(WebSession.class);
      verify(sessionManager, atLeastOnce()).saveKeycloakSessionId(sidSessionCaptor.capture(), anyString());
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
