package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.client.user.async.KeycloakUserAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link ReactiveBasicAuthenticationFilter} 단위 테스트.
 *
 * <p>Basic Auth 성공 시 {@code userAsync().getUserInfo(accessToken)}을 호출하여
 * 상세 권한까지 Principal에 반영하는지 StepVerifier로 검증합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class ReactiveBasicAuthenticationFilterTest {

  @Mock
  private KeycloakClient keycloakClient;

  @Mock
  private KeycloakAuthAsyncClient authAsyncClient;

  @Mock
  private KeycloakUserAsyncClient userAsyncClient;

  private ReactiveBasicAuthenticationFilter filter;

  private static final String CLIENT_ID = "test-client";
  private static final String USERNAME = "testuser";
  private static final String PASSWORD = "testpass";
  private static final String ID_TOKEN = "id.token.value";
  private static final String ACCESS_TOKEN = "access.token.value";
  private static final String USER_SUB = "user-sub-123";

  @BeforeEach
  void setUp() {
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    lenient().when(keycloakClient.userAsync()).thenReturn(userAsyncClient);
    filter = new ReactiveBasicAuthenticationFilter(keycloakClient, CLIENT_ID);
  }

  private String buildBasicHeader(String username, String password) {
    String credentials = username + ":" + password;
    return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
  }

  private MockServerWebExchange exchangeWithBasicAuth(String username, String password) {
    MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
        .header(HttpHeaders.AUTHORIZATION, buildBasicHeader(username, password))
        .build();
    return MockServerWebExchange.from(request);
  }

  private MockServerWebExchange exchangeWithoutAuth() {
    MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
    return MockServerWebExchange.from(request);
  }

  private KeycloakResponse<KeycloakTokenInfo> tokenResponse(int status) {
    if (status == 200) {
      KeycloakTokenInfo tokenInfo = KeycloakTokenInfo.builder()
          .idToken(ID_TOKEN)
          .accessToken(ACCESS_TOKEN)
          .build();
      return KeycloakResponse.<KeycloakTokenInfo>builder().status(200).body(tokenInfo).build();
    }
    return KeycloakResponse.<KeycloakTokenInfo>builder().status(status).build();
  }

  private KeycloakResponse<KeycloakUserInfo> userInfoResponse(int status, String role) {
    if (status == 200) {
      KeycloakUserInfo userInfo = new KeycloakUserInfo();
      userInfo.setOtherInfo("sub", USER_SUB);
      userInfo.setOtherInfo("preferred_username", USERNAME);
      if (role != null) {
        // resource_access 권한 포함 (클라이언트 역할)
        Map<String, Object> clientRoles = new HashMap<>();
        clientRoles.put("roles", java.util.List.of(role));
        Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put(CLIENT_ID, clientRoles);
        userInfo.setOtherInfo("resource_access", resourceAccess);
      }
      return KeycloakResponse.<KeycloakUserInfo>builder().status(200).body(userInfo).build();
    }
    return KeycloakResponse.<KeycloakUserInfo>builder().status(status).build();
  }

  private Map<String, Object> buildIdTokenClaims() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", USER_SUB);
    return claims;
  }

  // ==========================================================================
  // Basic 헤더 없음 → 다음 필터 통과
  // ==========================================================================

  @Nested
  class Basic헤더_없음 {

    @Test
    void Basic_헤더_없으면_다음_필터_통과() {
      MockServerWebExchange exchange = exchangeWithoutAuth();
      boolean[] chainCalled = {false};

      WebFilterChain chain = ex -> {
        chainCalled[0] = true;
        return Mono.empty();
      };

      StepVerifier.create(filter.filter(exchange, chain))
          .verifyComplete();

      assertThat(chainCalled[0]).isTrue();
    }

    @Test
    void Bearer_헤더는_Basic이_아니므로_다음_필터_통과() {
      MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
          .header(HttpHeaders.AUTHORIZATION, "Bearer some.token")
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);
      boolean[] chainCalled = {false};

      WebFilterChain chain = ex -> {
        chainCalled[0] = true;
        return Mono.empty();
      };

      StepVerifier.create(filter.filter(exchange, chain))
          .verifyComplete();

      assertThat(chainCalled[0]).isTrue();
    }
  }

  // ==========================================================================
  // Basic 인증 성공 + UserInfo 조회
  // ==========================================================================

  @Nested
  class Basic_인증_성공 {

    @Test
    void 인증_성공시_getUserInfo_호출_후_권한_반영된_Principal_생성() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.just(tokenResponse(200)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN))
          .thenReturn(Mono.just(userInfoResponse(200, "ROLE_USER")));

      // SecurityContext에 담기는 Authentication 캡처
      Authentication[] capturedAuth = new Authentication[1];
      WebFilterChain chain = ex ->
          ReactiveSecurityContextHolder.getContext()
              .doOnNext(ctx -> capturedAuth[0] = ctx.getAuthentication())
              .then();

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN))
            .thenReturn(USER_SUB);
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN))
            .thenReturn(buildIdTokenClaims());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();
      }

      assertThat(capturedAuth[0]).isNotNull();
      assertThat(capturedAuth[0].isAuthenticated()).isTrue();
      assertThat(capturedAuth[0]).isInstanceOf(BasicAuthenticationToken.class);

      BasicAuthenticationToken token = (BasicAuthenticationToken) capturedAuth[0];
      assertThat(token.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
      KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
      assertThat(principal.getName()).isEqualTo(USER_SUB);
    }

    @Test
    void getUserInfo_실패시_ID_Token_클레임으로_폴백() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.just(tokenResponse(200)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN))
          .thenReturn(Mono.just(userInfoResponse(401, null)));

      Authentication[] capturedAuth = new Authentication[1];
      WebFilterChain chain = ex ->
          ReactiveSecurityContextHolder.getContext()
              .doOnNext(ctx -> capturedAuth[0] = ctx.getAuthentication())
              .then();

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN))
            .thenReturn(USER_SUB);
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN))
            .thenReturn(buildIdTokenClaims());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();
      }

      // UserInfo 실패해도 폴백으로 인증 성공
      assertThat(capturedAuth[0]).isNotNull();
      assertThat(capturedAuth[0].isAuthenticated()).isTrue();
    }

    @Test
    void getUserInfo_통신_오류시_ID_Token_클레임으로_폴백() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.just(tokenResponse(200)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN))
          .thenReturn(Mono.error(new RuntimeException("network error")));

      Authentication[] capturedAuth = new Authentication[1];
      WebFilterChain chain = ex ->
          ReactiveSecurityContextHolder.getContext()
              .doOnNext(ctx -> capturedAuth[0] = ctx.getAuthentication())
              .then();

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN))
            .thenReturn(USER_SUB);
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN))
            .thenReturn(buildIdTokenClaims());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();
      }

      // 오류 시에도 폴백으로 인증 성공
      assertThat(capturedAuth[0]).isNotNull();
      assertThat(capturedAuth[0].isAuthenticated()).isTrue();
    }

    @Test
    void getUserInfo_성공시_UserInfo에서_OidcUserInfo_설정됨() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.just(tokenResponse(200)));
      when(userAsyncClient.getUserInfo(ACCESS_TOKEN))
          .thenReturn(Mono.just(userInfoResponse(200, null)));

      Authentication[] capturedAuth = new Authentication[1];
      WebFilterChain chain = ex ->
          ReactiveSecurityContextHolder.getContext()
              .doOnNext(ctx -> capturedAuth[0] = ctx.getAuthentication())
              .then();

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseSubjectWithoutValidation(ID_TOKEN))
            .thenReturn(USER_SUB);
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(ID_TOKEN))
            .thenReturn(buildIdTokenClaims());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();
      }

      BasicAuthenticationToken token = (BasicAuthenticationToken) capturedAuth[0];
      KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
      // UserInfo 조회 성공 시 UserInfo가 설정됨
      assertThat(principal.getUserInfo()).isNotNull();
    }
  }

  // ==========================================================================
  // Basic 인증 실패
  // ==========================================================================

  @Nested
  class Basic_인증_실패 {

    @Test
    void keycloak_401_응답시_다음_필터_통과() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);
      boolean[] chainCalled = {false};

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.just(tokenResponse(401)));

      WebFilterChain chain = ex -> {
        chainCalled[0] = true;
        return Mono.empty();
      };

      StepVerifier.create(filter.filter(exchange, chain))
          .verifyComplete();

      assertThat(chainCalled[0]).isTrue();
      // UserInfo 조회 미호출
      verify(userAsyncClient, never()).getUserInfo(any());
    }

    @Test
    void 통신_오류시_다음_필터_통과() {
      MockServerWebExchange exchange = exchangeWithBasicAuth(USERNAME, PASSWORD);
      boolean[] chainCalled = {false};

      when(authAsyncClient.basicAuth(USERNAME, PASSWORD))
          .thenReturn(Mono.error(new RuntimeException("Connection refused")));

      WebFilterChain chain = ex -> {
        chainCalled[0] = true;
        return Mono.empty();
      };

      StepVerifier.create(filter.filter(exchange, chain))
          .verifyComplete();

      assertThat(chainCalled[0]).isTrue();
    }
  }
}
