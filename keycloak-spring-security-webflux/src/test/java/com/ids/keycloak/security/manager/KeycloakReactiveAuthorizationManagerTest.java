package com.ids.keycloak.security.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link KeycloakReactiveAuthorizationManager} 단위 테스트.
 *
 * <p>flat mock 방식으로 deep stub UnfinishedStubbing 을 회피합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakReactiveAuthorizationManagerTest {

  private KeycloakReactiveAuthorizationManager manager;

  @Mock
  private KeycloakClient keycloakClient;

  @Mock
  private KeycloakAuthAsyncClient authAsyncClient;

  private static final String ACCESS_TOKEN = "test-access-token";
  private static final String REQUEST_URI = "/api/resource";
  private static final String REQUEST_METHOD = "GET";

  @BeforeEach
  void setUp() {
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    manager = new KeycloakReactiveAuthorizationManager(keycloakClient);
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private AuthorizationContext mockContext() {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(org.springframework.http.HttpMethod.GET, REQUEST_URI)
        .build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);
    AuthorizationContext context = mock(AuthorizationContext.class);
    when(context.getExchange()).thenReturn(exchange);
    return context;
  }

  private KeycloakAuthentication buildKeycloakAuth(boolean authenticated) {
    OidcIdToken oidcIdToken = new OidcIdToken(
        "token", Instant.now(), Instant.now().plusSeconds(3600), Map.of("sub", "user-1"));
    KeycloakPrincipal principal =
        new KeycloakPrincipal("user-1", Collections.emptyList(), oidcIdToken, null);
    return new KeycloakAuthentication(principal, "token", ACCESS_TOKEN, authenticated);
  }

  private KeycloakResponse<KeycloakAuthorizationResult> grantedResponse(boolean granted) {
    KeycloakAuthorizationResult result = KeycloakAuthorizationResult.builder()
        .granted(granted)
        .build();
    return KeycloakResponse.<KeycloakAuthorizationResult>builder()
        .status(200)
        .body(result)
        .build();
  }

  // ==========================================================================
  // 허용
  // ==========================================================================

  @Nested
  class 인가_허용 {

    @Test
    void KeycloakAuthentication_인증됨_Keycloak_허용_true_반환() {
      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.just(grantedResponse(true)));

      StepVerifier.create(manager.check(Mono.just(buildKeycloakAuth(true)), mockContext()))
          .expectNextMatches(AuthorizationDecision::isGranted)
          .verifyComplete();
    }

    @Test
    void BearerTokenAuthentication_인증됨_Keycloak_허용_true_반환() {
      BearerTokenAuthentication bearerAuth = mock(BearerTokenAuthentication.class);
      OAuth2AccessToken oauthToken = mock(OAuth2AccessToken.class);
      when(bearerAuth.isAuthenticated()).thenReturn(true);
      when(bearerAuth.getToken()).thenReturn(oauthToken);
      when(oauthToken.getTokenValue()).thenReturn(ACCESS_TOKEN);

      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.just(grantedResponse(true)));

      StepVerifier.create(manager.check(Mono.just(bearerAuth), mockContext()))
          .expectNextMatches(AuthorizationDecision::isGranted)
          .verifyComplete();
    }

    @Test
    void BasicAuthenticationToken_AccessTokenHolder_인증됨_허용_true_반환() {
      BasicAuthenticationToken basicAuth = mock(BasicAuthenticationToken.class);
      when(basicAuth.isAuthenticated()).thenReturn(true);
      when(basicAuth.getAccessToken()).thenReturn(ACCESS_TOKEN);

      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.just(grantedResponse(true)));

      StepVerifier.create(manager.check(Mono.just(basicAuth), mockContext()))
          .expectNextMatches(AuthorizationDecision::isGranted)
          .verifyComplete();
    }
  }

  // ==========================================================================
  // 거부
  // ==========================================================================

  @Nested
  class 인가_거부 {

    @Test
    void Keycloak_거부_false_반환() {
      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.just(grantedResponse(false)));

      StepVerifier.create(manager.check(Mono.just(buildKeycloakAuth(true)), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }

    @Test
    void Keycloak_응답_body_없으면_false_반환() {
      KeycloakResponse<KeycloakAuthorizationResult> emptyResp =
          KeycloakResponse.<KeycloakAuthorizationResult>builder().status(200).build();

      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.just(emptyResp));

      StepVerifier.create(manager.check(Mono.just(buildKeycloakAuth(true)), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }

    @Test
    void Keycloak_통신_오류시_false_반환() {
      when(authAsyncClient.authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
          .thenReturn(Mono.error(new RuntimeException("Connection refused")));

      StepVerifier.create(manager.check(Mono.just(buildKeycloakAuth(true)), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }
  }

  // ==========================================================================
  // 미인증 / 미지원 타입
  // ==========================================================================

  @Nested
  class 미인증_또는_미지원_타입 {

    @Test
    void 미인증_Authentication_false_반환() {
      // 미인증 → Mono.filter 에서 empty → defaultIfEmpty(false)
      StepVerifier.create(manager.check(Mono.just(buildKeycloakAuth(false)), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }

    @Test
    void empty_Mono_false_반환() {
      StepVerifier.create(manager.check(Mono.empty(), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }

    @Test
    void UsernamePasswordAuthenticationToken_미지원_타입_false_반환() {
      // UsernamePasswordAuthenticationToken 은 인증됨 상태지만 AccessTokenHolder 도 BearerToken 도 아님
      // extractAccessToken → null → filter(null) → empty → defaultIfEmpty(false)
      Authentication unsupported = new UsernamePasswordAuthenticationToken(
          "user", "pass", Collections.emptyList());

      StepVerifier.create(manager.check(Mono.just(unsupported), mockContext()))
          .expectNextMatches(decision -> !decision.isGranted())
          .verifyComplete();
    }
  }
}
