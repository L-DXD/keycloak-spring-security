package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.TokenBindingException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.client.user.async.KeycloakUserAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link KeycloakReactiveAuthenticationManager} 단위 테스트.
 *
 * <p>Mono 체이닝이 런타임에 실제로 동작하는지 {@link StepVerifier}로 검증합니다.
 * {@link KeycloakClient}를 flat mock 으로 분리하여 deep stub 의 UnfinishedStubbing 문제를 방지합니다.</p>
 *
 * <p><b>보안 Advisory 1 테스트:</b> ID Token/Access Token/UserInfo의 sub/aud/azp 결합 검증을
 * {@link #결합_검증_테스트} 에서 검증합니다.</p>
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

  @Mock
  private ReactiveJwtDecoder jwtDecoder;

  private static final String CLIENT_ID = "test-client";
  private static final String USER_SUB = "user-sub-123";
  private static final String OTHER_USER_SUB = "user-sub-456";
  private static final String ID_TOKEN_VAL = "valid-id-token";
  private static final String ACCESS_TOKEN_VAL = "valid-access-token";

  @BeforeEach
  void setUp() {
    // lenient: 인증 실패 테스트에서 userAsync 가 사용되지 않아도 UnnecessaryStubbingException 방지
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    lenient().when(keycloakClient.userAsync()).thenReturn(userAsyncClient);
    manager = new KeycloakReactiveAuthenticationManager(keycloakClient, CLIENT_ID, jwtDecoder);
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

  /** 서명 검증을 통과한 것으로 간주되는(테스트 더블) ID Token {@link Jwt}를 생성합니다. */
  private Jwt buildJwt(String tokenValue, String subject, List<String> audience, String azp) {
    Instant now = Instant.now();
    Jwt.Builder builder = Jwt.withTokenValue(tokenValue)
        .header("alg", "RS256")
        .subject(subject)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(3600));
    if (audience != null) {
      builder.audience(audience);
    }
    if (azp != null) {
      builder.claim("azp", azp);
    }
    return builder.build();
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

  private KeycloakResponse<KeycloakUserInfo> userInfoOk(String subject) {
    KeycloakUserInfo info = new KeycloakUserInfo();
    info.setOtherInfo("preferred_username", "testuser");
    info.setOtherInfo("sub", subject);
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
          .thenReturn(Mono.just(userInfoOk(USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID)));

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

  // ==========================================================================
  // 보안 Advisory 1: 토큰 결합 검증
  // ==========================================================================

  @Nested
  class 결합_검증_테스트 {

    @BeforeEach
    void setUpIntrospectSuccess() {
      lenient().when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
    }

    @Test
    void A의_ID_Token과_B의_Access_Token_조합이면_TokenBindingException이_발생한다() {
      // ID Token은 사용자 A(USER_SUB), UserInfo(Access Token 소유자)는 사용자 B(OTHER_USER_SUB)
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk(OTHER_USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof TokenBindingException
              && e.getMessage().contains("subject"))
          .verify();
    }

    @Test
    void ID_Token_서명_검증_실패시_TokenBindingException이_발생한다() {
      // authenticate()는 UserInfo 조회 후 createAuthenticatedToken(ID Token 디코딩)을 호출하므로
      // UserInfo 스텁이 없으면 언스텁 mock이 null을 반환해 NPE로 위장될 수 있어 명시적으로 스텁한다.
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk(USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.error(new BadJwtException("잘못된 issuer 또는 서명입니다.")));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof TokenBindingException)
          .verify();
    }

    @Test
    void ID_Token_만료시_TokenBindingException이_발생한다() {
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk(USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.error(new BadJwtException("Jwt expired at " + Instant.now().minusSeconds(10))));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof TokenBindingException)
          .verify();
    }

    @Test
    void ID_Token_aud에_client_id가_없으면_TokenBindingException이_발생한다() {
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk(USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of("other-client-id"), null)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof TokenBindingException
              && e.getMessage().contains("aud"))
          .verify();
    }

    @Test
    void ID_Token_azp가_client_id와_다르면_TokenBindingException이_발생한다() {
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoOk(USER_SUB)));
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), "malicious-client-id")));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(e -> e instanceof TokenBindingException
              && e.getMessage().contains("azp"))
          .verify();
    }
  }

  // ==========================================================================
  // N-2 회귀 방지: require-user-info 플래그 동작 — servlet(N-1)과 동일 정책
  // ==========================================================================

  @Nested
  class requireUserInfo_플래그_동작 {

    @BeforeEach
    void setUpIdTokenDecodeDefault() {
      lenient().when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID)));
    }

    // ------------------------------------------------------------------
    // require-user-info=false (기본값) — 모든 실패 경로 → 빈권한 성공
    // ------------------------------------------------------------------

    @Test
    void requireUserInfo_false_userinfo_빈body_200_인증_성공_빈권한() {
      // 200 + 빈 body → Mono.empty() → switchIfEmpty → null UserInfo → 빈권한 성공
      KeycloakResponse<KeycloakUserInfo> emptyBodyResp =
          KeycloakResponse.<KeycloakUserInfo>builder().status(200).build();
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(emptyBodyResp));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectNextMatches(auth -> {
            assertThat(auth.isAuthenticated()).isTrue();
            assertThat(auth.getAuthorities()).isEmpty();
            return true;
          })
          .verifyComplete();
    }

    @Test
    void requireUserInfo_false_userinfo_401_인증_성공_빈권한() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoFail(401)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectNextMatches(auth -> {
            assertThat(auth.isAuthenticated()).isTrue();
            assertThat(auth.getAuthorities()).isEmpty();
            return true;
          })
          .verifyComplete();
    }

    @Test
    void requireUserInfo_false_userinfo_503_인증_성공_빈권한() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoFail(503)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectNextMatches(auth -> {
            assertThat(auth.isAuthenticated()).isTrue();
            assertThat(auth.getAuthorities()).isEmpty();
            return true;
          })
          .verifyComplete();
    }

    /**
     * 순수 RuntimeException 통신 오류는 onErrorResume 에서 잡혀 handleUserInfoFailureReactive 호출.
     * requireUserInfo=false → Mono.empty() → switchIfEmpty → 빈권한 인증 성공.
     */
    @Test
    void requireUserInfo_false_RuntimeException_오류시_빈권한_인증_성공() {
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.error(new RuntimeException("network error")));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectNextMatches(auth -> {
            assertThat(auth.isAuthenticated()).isTrue();
            assertThat(auth.getAuthorities()).isEmpty();
            return true;
          })
          .verifyComplete();
    }

    // ------------------------------------------------------------------
    // require-user-info=true — 모든 실패 경로 → 인증 실패(UserInfoFetchException)
    // ------------------------------------------------------------------

    @Test
    void requireUserInfo_true_userinfo_빈body_200_인증_실패() {
      manager.setRequireUserInfo(true);

      KeycloakResponse<KeycloakUserInfo> emptyBodyResp =
          KeycloakResponse.<KeycloakUserInfo>builder().status(200).build();
      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(emptyBodyResp));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(
              e -> e instanceof com.ids.keycloak.security.exception.UserInfoFetchException)
          .verify();
    }

    @Test
    void requireUserInfo_true_userinfo_401_인증_실패() {
      manager.setRequireUserInfo(true);

      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoFail(401)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(
              e -> e instanceof com.ids.keycloak.security.exception.UserInfoFetchException
                  && e.getMessage().contains("401"))
          .verify();
    }

    @Test
    void requireUserInfo_true_userinfo_503_인증_실패() {
      manager.setRequireUserInfo(true);

      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.just(userInfoFail(503)));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(
              e -> e instanceof com.ids.keycloak.security.exception.UserInfoFetchException)
          .verify();
    }

    @Test
    void requireUserInfo_true_RuntimeException_오류시_인증_실패() {
      manager.setRequireUserInfo(true);

      when(authAsyncClient.authenticationByIntrospect(ID_TOKEN_VAL))
          .thenReturn(Mono.just(introspectOk(true)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN_VAL))
          .thenReturn(Mono.error(new RuntimeException("network error")));

      StepVerifier.create(manager.authenticate(buildAuthRequest(ID_TOKEN_VAL, ACCESS_TOKEN_VAL)))
          .expectErrorMatches(
              e -> e instanceof com.ids.keycloak.security.exception.UserInfoFetchException)
          .verify();
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
  // createAuthenticatedToken (직접 호출 — refreshAndAuthenticate 에서 사용, Refresh 경로도 동일 검증)
  // ==========================================================================

  @Nested
  class createAuthenticatedToken_직접_호출 {

    @Test
    void userinfo_null_전달시_인증된_Authentication_반환() {
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID)));

      StepVerifier.create(manager.createAuthenticatedToken(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, null))
          .expectNextMatches(result -> {
            assertThat(result.isAuthenticated()).isTrue();
            assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
            assertThat(((KeycloakPrincipal) result.getPrincipal()).getName()).isEqualTo(USER_SUB);
            return true;
          })
          .verifyComplete();
    }

    @Test
    void Refresh로_재발급된_토큰_조합도_결합검증을_통과해야_한다() {
      // Refresh 후 재발급된 ID/Access Token 조합이 서로 다른 사용자면 Refresh 경로에서도 실패해야 함
      when(jwtDecoder.decode(ID_TOKEN_VAL))
          .thenReturn(Mono.just(buildJwt(ID_TOKEN_VAL, USER_SUB, List.of(CLIENT_ID), CLIENT_ID)));

      org.springframework.security.oauth2.core.oidc.OidcUserInfo otherUserInfo =
          new org.springframework.security.oauth2.core.oidc.OidcUserInfo(Map.of("sub", OTHER_USER_SUB));

      StepVerifier.create(
              manager.createAuthenticatedToken(ID_TOKEN_VAL, ACCESS_TOKEN_VAL, otherUserInfo))
          .expectErrorMatches(e -> e instanceof TokenBindingException)
          .verify();
    }
  }
}
