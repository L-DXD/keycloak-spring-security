package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.client.user.async.KeycloakUserAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link KeycloakReactiveAuthenticationManager} 단위 테스트.
 *
 * <p>Mono 체이닝이 런타임에 실제로 동작하는지 {@link StepVerifier}로 검증합니다.
 * {@link KeycloakClient}를 flat mock 으로 분리하여 deep stub 의 UnfinishedStubbing 문제를 방지합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakReactiveAuthenticationManagerTest {

  private KeycloakReactiveAuthenticationManager manager;

  /** KeycloakClient 자체는 일반 mock — authAsync/userAsync 를 직접 stub */
  @Mock
  private KeycloakClient keycloakClient;

  @Mock
  private KeycloakAuthAsyncClient authAsyncClient;

  @Mock
  private KeycloakUserAsyncClient userAsyncClient;

  private static final String CLIENT_ID = "test-client";
  private static final String USER_SUB = "user-sub-123";
  private static final String ID_TOKEN_VAL = "valid.id.token";
  private static final String ACCESS_TOKEN_VAL = "valid.access.token";

  @BeforeEach
  void setUp() {
    // lenient: 인증 실패 테스트에서 userAsync 가 사용되지 않아도 UnnecessaryStubbingException 방지
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    lenient().when(keycloakClient.userAsync()).thenReturn(userAsyncClient);
    manager = new KeycloakReactiveAuthenticationManager(keycloakClient, CLIENT_ID);
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private KeycloakAuthentication buildAuthRequest(String idToken, String accessToken) {
    OidcIdToken oidcIdToken = new OidcIdToken(
        idToken, Instant.now(), Instant.now().plusSeconds(3600), Map.of("sub", USER_SUB));
    KeycloakPrincipal principal =
        new KeycloakPrincipal(USER_SUB, Collections.emptyList(), oidcIdToken, null);
    return new KeycloakAuthentication(principal, idToken, accessToken, false);
  }

  private KeycloakResponse<KeycloakIntrospectResponse> introspectOk(boolean active) {
    return KeycloakResponse.<KeycloakIntrospectResponse>builder()
        .status(200)
        .body(new KeycloakIntrospectResponse(active))
        .build();
  }

  private KeycloakResponse<KeycloakIntrospectResponse> introspectFail(int status) {
    return KeycloakResponse.<KeycloakIntrospectResponse>builder()
        .status(status)
        .build();
  }

  private KeycloakResponse<KeycloakUserInfo> userInfoOk() {
    KeycloakUserInfo info = new KeycloakUserInfo();
    info.setOtherInfo("preferred_username", "testuser");
    return KeycloakResponse.<KeycloakUserInfo>builder()
        .status(200)
        .body(info)
        .build();
  }

  private KeycloakResponse<KeycloakUserInfo> userInfoFail(int status) {
    return KeycloakResponse.<KeycloakUserInfo>builder()
        .status(status)
        .build();
  }

  private Map<String, Object> buildClaims() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", USER_SUB);
    claims.put("iat", Instant.now().getEpochSecond());
    claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());
    return claims;
  }

  // ==========================================================================
  // 인증 성공
  // ==========================================================================

  @Nested
  class 인증_성공 {

    @Test
    void introspect_200_active_true_userinfo_200_정상_인증완료() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk()));

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(buildClaims());
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(USER_SUB);

        StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
            .expectNextMatches(auth -> {
              assertThat(auth.isAuthenticated()).isTrue();
              assertThat(auth.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
              assertThat(((KeycloakPrincipal) auth.getPrincipal()).getName()).isEqualTo(USER_SUB);
              assertThat(auth).isInstanceOf(KeycloakAuthentication.class);
              return true;
            })
            .verifyComplete();
      }
    }
  }

  // ==========================================================================
  // UserInfo fallback 동작 검증
  // ==========================================================================

  @Nested
  class UserInfo_fallback {

    /**
     * UserInfoFetchException 은 KeycloakSecurityException → RuntimeException 상속.
     * {@code fetchUserInfo} 의 onErrorResume 조건은 {@code !(e instanceof KeycloakSecurityException)} 도 체크하므로
     * → onErrorResume 이 적용되지 않아 UserInfoFetchException 이 전파됨.
     * → 최상위 onErrorResume 도 KeycloakSecurityException 은 통과시키므로 에러 전파.
     */
    @Test
    void userinfo_401_UserInfoFetchException_전파() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoFail(401)));

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(buildClaims());
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(USER_SUB);

        StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
            .expectError(com.ids.keycloak.security.exception.UserInfoFetchException.class)
            .verify();
      }
    }

    /**
     * 순수 RuntimeException 통신 오류는 onErrorResume 에서 잡혀 Mono.empty() 반환.
     * switchIfEmpty 에서 createAuthenticatedToken(null) 호출 → 인증 성공.
     */
    @Test
    void userinfo_RuntimeException_오류시_null_fallback_인증_성공() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.error(new RuntimeException("network error")));

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(buildClaims());
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN_VAL))
            .thenReturn(USER_SUB);

        StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
            .expectNextMatches(auth -> {
              assertThat(auth.isAuthenticated()).isTrue();
              return true;
            })
            .verifyComplete();
      }
    }
  }

  // ==========================================================================
  // 인증 실패
  // ==========================================================================

  @Nested
  class 인증_실패 {

    @Test
    void introspect_200_active_false_IntrospectionFailedException_발생() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(false)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e ->
              e instanceof IntrospectionFailedException
                  && e.getMessage().contains("유효하지 않습니다"))
          .verify();
    }

    @Test
    void introspect_401_IntrospectionFailedException_발생() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectFail(401)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof IntrospectionFailedException)
          .verify();
    }

    @Test
    void introspect_500_ConfigurationException_발생() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectFail(500)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e ->
              e instanceof ConfigurationException
                  && e.getMessage().contains("Keycloak 서버"))
          .verify();
    }

    @Test
    void introspect_body_없음_IntrospectionFailedException_발생() {
      // status 200 + body null
      KeycloakResponse<KeycloakIntrospectResponse> resp =
          KeycloakResponse.<KeycloakIntrospectResponse>builder().status(200).build();
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(resp));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof IntrospectionFailedException)
          .verify();
    }

    @Test
    void introspect_통신_오류_ConfigurationException_으로_래핑() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.error(new RuntimeException("Connection refused")));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e ->
              e instanceof ConfigurationException
                  && e.getMessage().contains("통신"))
          .verify();
    }

    @Test
    void introspect_기타_상태코드_AuthenticationFailedException_발생() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectFail(403)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof AuthenticationFailedException)
          .verify();
    }
  }

  // ==========================================================================
  // createAuthenticatedToken (직접 호출 — refreshAndAuthenticate 에서 사용)
  // ==========================================================================

  @Nested
  class createAuthenticatedToken_직접_호출 {

    @Test
    void userinfo_null_전달시_인증된_Authentication_반환() {
      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(anyString()))
            .thenReturn(buildClaims());
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
            .thenReturn(USER_SUB);

        Authentication result =
            manager.createAuthenticatedToken(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, null);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
        assertThat(((KeycloakPrincipal) result.getPrincipal()).getName()).isEqualTo(USER_SUB);
      }
    }
  }
}
