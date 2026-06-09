package com.ids.keycloak.security.authentication;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.model.KeycloakLogoutToken;
import com.ids.keycloak.security.util.JwtUtil;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.session.ReactiveFindByIndexNameSessionRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link ReactiveOidcBackChannelLogoutHandler} 단위 테스트.
 *
 * <p>{@link ReactiveFindByIndexNameSessionRepository}를 mock하여
 * logout_token 파싱 → 세션 무효화 호출 여부를 StepVerifier로 검증합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class ReactiveOidcBackChannelLogoutHandlerTest {

  @Mock
  private TestSessionRepository sessionRepository;

  private ReactiveOidcBackChannelLogoutHandler handler;

  private static final String SUBJECT = "user-sub-123";
  private static final String KEYCLOAK_SID = "kcSid-abc";
  private static final String LOGOUT_TOKEN_JWT = "logout.token.jwt";
  private static final String SPRING_SESSION_ID = "spring-session-id-1";

  /**
   * 테스트용 combined 인터페이스: ReactiveFindByIndexNameSessionRepository + ReactiveSessionRepository
   */
  interface TestSessionRepository
      extends ReactiveFindByIndexNameSessionRepository<Session>,
      ReactiveSessionRepository<Session> {
  }

  @BeforeEach
  void setUp() {
    handler = new ReactiveOidcBackChannelLogoutHandler(sessionRepository);
  }

  private WebFilterExchange mockWebFilterExchange() {
    MockServerHttpRequest request = MockServerHttpRequest.post("/logout/connect/back-channel/keycloak").build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);
    return new WebFilterExchange(exchange, chain -> Mono.empty());
  }

  private Map<String, Object> buildLogoutTokenClaims(String sub, String sid) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", "http://keycloak/realms/test");
    if (sub != null) {
      claims.put("sub", sub);
    }
    if (sid != null) {
      claims.put("sid", sid);
    }
    // 표준 back-channel logout 이벤트 클레임
    Map<String, Object> events = new HashMap<>();
    events.put("http://schemas.openid.net/event/backchannel-logout", new HashMap<>());
    claims.put("events", events);
    return claims;
  }

  private Session mockSessionWithSid(String keycloakSid) {
    Session session = mock(Session.class);
    lenient().when(session.getAttribute(ReactiveOidcBackChannelLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
        .thenReturn(keycloakSid);
    return session;
  }

  // ==========================================================================
  // 정상 케이스
  // ==========================================================================

  @Nested
  class 정상_케이스 {

    @Test
    void logout_token_sub_sid_모두_있으면_매칭_세션_deleteById_호출() {
      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      when(sessionRepository.findByPrincipalName(SUBJECT))
          .thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID))
          .thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(LOGOUT_TOKEN_JWT))
            .thenReturn(buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID));

        StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
            .verifyComplete();
      }

      verify(sessionRepository).findByPrincipalName(SUBJECT);
      verify(sessionRepository).deleteById(SPRING_SESSION_ID);
    }

    @Test
    void logout_token_sub만_있고_sid_없으면_모든_세션_deleteById_호출() {
      Session session1 = mockSessionWithSid(null);
      Session session2 = mockSessionWithSid(null);
      Map<String, Session> sessions = Map.of("session-1", session1, "session-2", session2);

      when(sessionRepository.findByPrincipalName(SUBJECT))
          .thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(anyString()))
          .thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(LOGOUT_TOKEN_JWT))
            .thenReturn(buildLogoutTokenClaims(SUBJECT, null));

        StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
            .verifyComplete();
      }

      verify(sessionRepository).findByPrincipalName(SUBJECT);
    }

    @Test
    void sid_있어도_매칭_세션_없으면_deleteById_미호출() {
      // 세션은 있지만 KEYCLOAK_SID가 다름
      Session session = mockSessionWithSid("different-sid");
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      when(sessionRepository.findByPrincipalName(SUBJECT))
          .thenReturn(Mono.just(sessions));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(LOGOUT_TOKEN_JWT))
            .thenReturn(buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID));

        StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
            .verifyComplete();
      }

      verify(sessionRepository, never()).deleteById(anyString());
    }
  }

  // ==========================================================================
  // 오류 케이스
  // ==========================================================================

  @Nested
  class 오류_케이스 {

    @Test
    void authentication_null이면_BadRequest_응답() {
      StepVerifier.create(handler.logout(mockWebFilterExchange(), null))
          .verifyComplete();
    }

    @Test
    void credentials_null이면_BadRequest_응답() {
      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(null);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();
    }

    @Test
    void JWT_파싱_실패시_BadRequest_응답() {
      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(LOGOUT_TOKEN_JWT))
            .thenReturn(java.util.Collections.emptyMap());

        StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
            .verifyComplete();
      }

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }

    @Test
    void logout_token_이벤트_없으면_BadRequest_응답() {
      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      try (MockedStatic<JwtUtil> jwtMock = mockStatic(JwtUtil.class)) {
        // events 클레임 없는 토큰
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", SUBJECT);
        jwtMock.when(() -> JwtUtil.parseClaimsWithoutValidation(LOGOUT_TOKEN_JWT))
            .thenReturn(claims);

        StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
            .verifyComplete();
      }

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }
  }
}
