package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.client.user.async.KeycloakUserAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link KeycloakServerAuthenticationConverter} 단위 테스트.
 *
 * <p>{@code MockServerWebExchange}를 사용하여 쿠키 존재 여부에 따른 분기를 검증합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakServerAuthenticationConverterTest {

  @Mock
  private KeycloakReactiveAuthenticationManager authManager;

  @Mock
  private KeycloakClient keycloakClient;

  @Mock
  private KeycloakAuthAsyncClient authAsyncClient;

  @Mock
  private KeycloakUserAsyncClient userAsyncClient;

  @Mock
  private ReactiveSessionManager sessionManager;

  private KeycloakServerAuthenticationConverter converter;
  private KeycloakCookieProperties cookieProperties;

  private static final String ID_TOKEN = "test.id.token";
  private static final String ACCESS_TOKEN = "test.access.token";
  private static final String REFRESH_TOKEN = "test.refresh.token";

  @BeforeEach
  void setUp() {
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    lenient().when(keycloakClient.userAsync()).thenReturn(userAsyncClient);
    cookieProperties = new KeycloakCookieProperties();
    converter = new KeycloakServerAuthenticationConverter(
        authManager, keycloakClient, sessionManager, cookieProperties);
  }

  // ==========================================================================
  // 토큰 없음 → Mono.empty()
  // ==========================================================================

  @Nested
  class 토큰_없음 {

    @Test
    void id_token_쿠키_없으면_empty_Mono_반환() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }

    @Test
    void id_token_쿠키_있어도_세션에_refresh_token_없으면_empty_Mono_반환() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.empty());

      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }
  }

  // ==========================================================================
  // 토큰 있음 → 미인증 Authentication 생성 시도
  // ==========================================================================

  @Nested
  class 토큰_있음 {

    @Test
    void id_token_및_refresh_token_있으면_authManager_에_위임하고_Authentication_반환() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      // authManager.authenticate() 성공 반환
      Authentication authenticated = mock(Authentication.class);
      when(authenticated.isAuthenticated()).thenReturn(true);
      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.just(authenticated));

      StepVerifier.create(converter.convert(exchange))
          .expectNextMatches(Authentication::isAuthenticated)
          .verifyComplete();
    }

    /**
     * H-N1: 토큰 재발급 성공 시 session.save() Mono가 체인에 포함되어 실제 구독·실행되는지 검증.
     *
     * <p>수정 전 코드는 session.save() 반환 Mono를 체인에 연결하지 않아 구독이 발생하지 않았다.
     * 수정 후 {@code saveSession.then(...)} 체인에서 save()가 반드시 구독된다.</p>
     *
     * <p>검증 방식: {@code session.save()} 반환 Mono가 구독돼야만 이후 {@code .then(userInfo)} 체인이
     * 실행되므로, 파이프라인 끝까지 완료(onComplete)되고 {@code createAuthenticatedToken}이
     * 호출됐다면 save()도 구독됐다는 것을 의미한다.</p>
     */
    @Test
    void 재발급_성공시_session_save_체인_포함으로_파이프라인_완료_검증() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      // authManager 실패 → refresh 재시도 대상
      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(
              new com.ids.keycloak.security.exception.IntrospectionFailedException("토큰 만료")));

      // reissueToken 200 성공 (새 refreshToken 포함)
      KeycloakTokenInfo newTokens = KeycloakTokenInfo.builder()
          .accessToken("new.access.token")
          .idToken("new.id.token")
          .refreshToken("new.refresh.token")
          .expireTime(300)
          .build();
      KeycloakResponse<KeycloakTokenInfo> reissueResp =
          KeycloakResponse.<KeycloakTokenInfo>builder()
              .status(200)
              .body(newTokens)
              .build();
      when(authAsyncClient.reissueToken(REFRESH_TOKEN))
          .thenReturn(Mono.just(reissueResp));

      // UserInfo 조회 실패 → onErrorResume 경로로 null oidcUserInfo 인증 객체 반환
      when(userAsyncClient.getUserInfo(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(new RuntimeException("userinfo error")));

      Authentication fakeAuth = mock(Authentication.class);
      when(fakeAuth.isAuthenticated()).thenReturn(true);
      when(authManager.createAuthenticatedToken(
          org.mockito.ArgumentMatchers.any(),
          org.mockito.ArgumentMatchers.any(),
          org.mockito.ArgumentMatchers.isNull()))
          .thenReturn(fakeAuth);

      // H-N1 검증:
      // save()가 체인에 포함되지 않았다면 saveSession.then(userInfo) 자체가 cold Mono가 되어
      // 구독되지 않고 파이프라인이 중단됨 → StepVerifier가 onComplete을 받지 못한다.
      // 수정 후 save() 완료 → userInfo → onErrorResume → createAuthenticatedToken 순서로 실행.
      StepVerifier.create(converter.convert(exchange))
          .expectNextMatches(Authentication::isAuthenticated)
          .verifyComplete();

      // save() → then() 체인 이후 createAuthenticatedToken 호출 확인
      org.mockito.Mockito.verify(authManager).createAuthenticatedToken(
          org.mockito.ArgumentMatchers.any(),
          org.mockito.ArgumentMatchers.any(),
          org.mockito.ArgumentMatchers.isNull());
    }

    /**
     * 버그 수정 (#54): introspect 실패 후 refresh 재발급 401 → convert()가 빈 Mono 반환.
     *
     * <p>수정 전: RefreshTokenException(RuntimeException 계열)을 throw → AuthenticationWebFilter가
     * onErrorResume(AuthenticationException.class)로 잡지 못해 HTTP 500 발생.</p>
     *
     * <p>수정 후: 토큰 무효(400/401) → 세션 무효화 → Mono.empty() 반환
     * → AuthenticationWebFilter.switchIfEmpty(chain.filter(exchange)) → 미인증 진행
     * → ExceptionTranslationWebFilter → 사용처 EntryPoint(리다이렉트/401).</p>
     */
    @Test
    void introspect_실패_후_refresh_재발급_401_이면_빈_Mono_반환_non_AuthenticationException_미전파() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      // authManager 실패 — IntrospectionFailedException (refresh 재시도 대상)
      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(
              new com.ids.keycloak.security.exception.IntrospectionFailedException("토큰 만료")));

      // reissueToken — 401 응답 (refresh token도 무효)
      KeycloakResponse<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo> reissueResp =
          KeycloakResponse.<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo>builder()
              .status(401)
              .build();

      when(authAsyncClient.reissueToken(REFRESH_TOKEN))
          .thenReturn(Mono.just(reissueResp));

      when(sessionManager.invalidateSession(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.empty());

      // 수정 후: 빈 Mono → HTTP 500이 아닌 EntryPoint 경유(302/401)
      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }

    /**
     * 버그 수정 (#54): introspect 실패 후 refresh 재발급 400 → convert()가 빈 Mono 반환.
     *
     * <p>Keycloak 백채널 로그아웃 후 refresh token 재발급 시 400 응답 케이스 (#54 원인 시나리오).</p>
     */
    @Test
    void introspect_실패_후_refresh_재발급_400_이면_빈_Mono_반환() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(
              new com.ids.keycloak.security.exception.IntrospectionFailedException("active=false")));

      // reissueToken — 400 응답 (백채널 로그아웃 후 refresh token 폐기됨)
      KeycloakResponse<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo> reissueResp =
          KeycloakResponse.<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo>builder()
              .status(400)
              .build();

      when(authAsyncClient.reissueToken(REFRESH_TOKEN))
          .thenReturn(Mono.just(reissueResp));

      when(sessionManager.invalidateSession(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.empty());

      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }

    /**
     * 버그 수정 (#54): refresh 재발급 중 네트워크 오류 → convert()가 빈 Mono 반환.
     *
     * <p>RuntimeException이 convert() 밖으로 전파되면 HTTP 500이 발생하므로
     * 최종 방어막(onErrorResume)에서 Mono.empty()로 변환한다.</p>
     */
    @Test
    void refresh_재발급_중_네트워크_오류_이면_빈_Mono_반환_RuntimeException_미전파() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(
              new com.ids.keycloak.security.exception.IntrospectionFailedException("통신 오류")));

      // 네트워크 오류: reissueToken 자체가 예외 발생
      when(authAsyncClient.reissueToken(REFRESH_TOKEN))
          .thenReturn(Mono.error(new RuntimeException("Connection refused")));

      when(sessionManager.invalidateSession(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.empty());

      // RuntimeException이 convert()를 뚫고 나오면 HTTP 500 → 수정 후 빈 Mono
      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }

    /**
     * 버그 수정 (#54): introspect 실패 후 refresh 재발급 5xx 서버 오류 → convert()가 빈 Mono 반환.
     */
    @Test
    void introspect_실패_후_refresh_재발급_5xx_이면_빈_Mono_반환() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.error(
              new com.ids.keycloak.security.exception.IntrospectionFailedException("서버 오류")));

      // reissueToken — 500 응답 (Keycloak 서버 일시 오류)
      KeycloakResponse<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo> reissueResp =
          KeycloakResponse.<com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo>builder()
              .status(500)
              .build();

      when(authAsyncClient.reissueToken(REFRESH_TOKEN))
          .thenReturn(Mono.just(reissueResp));

      when(sessionManager.invalidateSession(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.empty());

      StepVerifier.create(converter.convert(exchange))
          .verifyComplete();
    }

    /**
     * 정상 경로 회귀: introspect 성공 시 Authentication 반환 (기존 동작 유지).
     */
    @Test
    void introspect_성공시_Authentication_정상_반환_회귀_없음() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ID_TOKEN_COOKIE_NAME, ID_TOKEN))
          .cookie(new HttpCookie(KeycloakServerAuthenticationConverter.ACCESS_TOKEN_COOKIE_NAME, ACCESS_TOKEN))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      when(sessionManager.getRefreshToken(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Optional.of(REFRESH_TOKEN));

      Authentication authenticated = mock(Authentication.class);
      when(authenticated.isAuthenticated()).thenReturn(true);
      when(authManager.authenticate(org.mockito.ArgumentMatchers.any()))
          .thenReturn(Mono.just(authenticated));

      StepVerifier.create(converter.convert(exchange))
          .expectNextMatches(Authentication::isAuthenticated)
          .verifyComplete();
    }
  }
}
