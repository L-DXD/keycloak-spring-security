package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ids.keycloak.security.model.KeycloakLogoutToken;
import com.ids.keycloak.security.util.LogMaskingUtil;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.session.ReactiveFindByIndexNameSessionRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link ReactiveOidcBackChannelLogoutHandler} 단위 테스트.
 *
 * <p><b>C-1 검증:</b> {@link ReactiveJwtDecoder}를 mock하여
 * 서명 검증 통과 시에만 세션 삭제가 수행되고,
 * 위조(서명 불일치) 토큰은 세션 삭제 없이 400을 반환함을 검증합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class ReactiveOidcBackChannelLogoutHandlerTest {

  @Mock
  private TestSessionRepository sessionRepository;

  @Mock
  private ReactiveJwtDecoder jwtDecoder;

  private ReactiveOidcBackChannelLogoutHandler handler;

  private static final String SUBJECT = "user-sub-123";
  private static final String KEYCLOAK_SID = "kcSid-abc";
  private static final String LOGOUT_TOKEN_JWT = "header.payload.signature";
  private static final String FORGED_TOKEN_JWT = "header.payload.forged-signature";
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
    handler = new ReactiveOidcBackChannelLogoutHandler(sessionRepository, jwtDecoder);
  }

  private WebFilterExchange mockWebFilterExchange() {
    MockServerHttpRequest request = MockServerHttpRequest
        .post("/logout/connect/back-channel/keycloak").build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);
    return new WebFilterExchange(exchange, chain -> Mono.empty());
  }

  /**
   * 유효한 back-channel logout JWT 클레임 맵을 생성합니다.
   */
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

  /**
   * 검증된 {@link Jwt} 객체를 빌드합니다.
   */
  private Jwt buildJwt(Map<String, Object> claims) {
    return Jwt.withTokenValue(LOGOUT_TOKEN_JWT)
        .header("alg", "RS256")
        .claims(c -> c.putAll(claims))
        .issuedAt(Instant.now().minusSeconds(10))
        .expiresAt(Instant.now().plusSeconds(300))
        .build();
  }

  private Session mockSessionWithSid(String keycloakSid) {
    Session session = mock(Session.class);
    lenient()
        .when(session.getAttribute(ReactiveOidcBackChannelLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
        .thenReturn(keycloakSid);
    return session;
  }

  // ==========================================================================
  // C-1 핵심: 서명 검증 통과/실패 케이스
  // ==========================================================================

  @Nested
  class C1_서명검증 {

    @Test
    void 위조_토큰은_서명검증_실패로_세션_삭제_없이_BadRequest_반환() {
      // Given: jwtDecoder가 위조 토큰에 대해 JwtException 던짐
      when(jwtDecoder.decode(FORGED_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("JWT signature does not match")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(FORGED_TOKEN_JWT);

      // When & Then
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // 세션 삭제가 절대 호출되지 않아야 함 (C-1 핵심 보장)
      verify(sessionRepository, never()).findByPrincipalName(anyString());
      verify(sessionRepository, never()).deleteById(anyString());
    }

    @Test
    void 만료된_토큰은_검증_실패로_세션_삭제_없이_BadRequest_반환() {
      // Given: 만료된 토큰
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("Jwt expired at ...")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When & Then
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }

    @Test
    void iss_불일치_토큰은_검증_실패로_세션_삭제_없이_BadRequest_반환() {
      // Given: issuer 불일치
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("The iss claim is not valid")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When & Then
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }

    @Test
    void 서명_검증_통과한_토큰은_세션_삭제_수행() {
      // Given: 정상 토큰 — jwtDecoder 검증 통과
      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));

      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID)).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When & Then
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository).findByPrincipalName(SUBJECT);
      verify(sessionRepository).deleteById(SPRING_SESSION_ID);
    }
  }

  // ==========================================================================
  // 정상 케이스 (서명 검증 통과 가정)
  // ==========================================================================

  @Nested
  class 정상_케이스 {

    @Test
    void logout_token_sub_sid_모두_있으면_매칭_세션_deleteById_호출() {
      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID)).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository).findByPrincipalName(SUBJECT);
      verify(sessionRepository).deleteById(SPRING_SESSION_ID);
    }

    @Test
    void logout_token_sub만_있고_sid_없으면_모든_세션_deleteById_호출() {
      Session session1 = mockSessionWithSid(null);
      Session session2 = mockSessionWithSid(null);
      Map<String, Session> sessions = Map.of("session-1", session1, "session-2", session2);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, null);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(anyString())).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository).findByPrincipalName(SUBJECT);
    }

    @Test
    void sid_있어도_매칭_세션_없으면_deleteById_미호출() {
      // 세션은 있지만 KEYCLOAK_SID가 다름
      Session session = mockSessionWithSid("different-sid");
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

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
    void jwtDecoder_오류시_BadRequest_응답_세션삭제_없음() {
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("Invalid token")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }

    @Test
    void logout_token_이벤트_없으면_BadRequest_응답() {
      // events 클레임 없는 토큰 (서명은 통과)
      Map<String, Object> claims = new HashMap<>();
      claims.put("sub", SUBJECT);
      claims.put("iss", "http://keycloak/realms/test");
      // events 클레임 없음 — isLogoutToken() == false

      Jwt noEventJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(noEventJwt));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
    }
  }

  // ==========================================================================
  // Advisory 5 리뷰 대응: 로그 원문 미노출 검증
  // ==========================================================================

  /**
   * Advisory 5 리뷰 대응: "로그에 토큰/식별자 원문이 안 나온다"를 실제로 검증하는 테스트가
   * 없었던 완료기준 미충족을 해소한다. Logback {@link ListAppender}로 핸들러가 실제로 남기는
   * 로그를 캡처하여, logout_token(JWT) 원문 및 sub/sid 원문이 어떤 레벨·경로에서도
   * 노출되지 않음을 검증한다.
   */
  @Nested
  class 로그_원문_미노출_검증 {

    private Logger handlerLogger;
    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUpLogCapture() {
      handlerLogger = (Logger) LoggerFactory.getLogger(ReactiveOidcBackChannelLogoutHandler.class);
      logAppender = new ListAppender<>();
      logAppender.start();
      handlerLogger.addAppender(logAppender);
      // 요구사항: DEBUG/TRACE 레벨까지 활성화한 상태에서도 원문 미출력을 검증
      handlerLogger.setLevel(Level.ALL);
    }

    @AfterEach
    void tearDownLogCapture() {
      handlerLogger.detachAppender(logAppender);
      logAppender.stop();
    }

    private List<String> formattedMessages() {
      return logAppender.list.stream()
          .map(ILoggingEvent::getFormattedMessage)
          .collect(Collectors.toList());
    }

    @Test
    void SID_삭제_경로에서_원문_JWT와_sub_sid가_로그에_노출되지_않는다() {
      // Given
      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID)).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // Then — 원문 미노출
      List<String> messages = formattedMessages();
      assertThat(messages).isNotEmpty();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
      assertThat(messages).noneMatch(m -> m.contains(KEYCLOAK_SID));

      // 마스킹된 형태로는 실제로 기록됨 — 어서션 무력화(로그 부재로 인한 거짓 통과) 방지
      assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(SUBJECT)));
      assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(KEYCLOAK_SID)));
    }

    @Test
    void sub만_있는_전체_세션_삭제_경로에서도_원문_JWT와_sub가_로그에_노출되지_않는다() {
      // Given
      Session session1 = mockSessionWithSid(null);
      Session session2 = mockSessionWithSid(null);
      Map<String, Session> sessions = Map.of("session-1", session1, "session-2", session2);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, null);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(anyString())).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
      assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(SUBJECT)));
    }

    @Test
    void 서명검증_실패_경로에서도_원문_JWT가_로그에_노출되지_않는다() {
      // Given — 위조된 토큰. JwtException 메시지 자체에는 원문 토큰이 없음을 전제로 함
      // (실제 라이브러리가 예외 메시지에 원문 JWT를 포함하는지는 이 mock 테스트의 범위 밖)
      when(jwtDecoder.decode(FORGED_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("JWT signature does not match")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(FORGED_TOKEN_JWT);

      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).isNotEmpty();
      assertThat(messages).noneMatch(m -> m.contains(FORGED_TOKEN_JWT));
      // 경고 로그 자체는 남아야 함 (positive control)
      assertThat(messages).anyMatch(m -> m.contains("서명/검증 실패"));
    }

    @Test
    void events_클레임_누락으로_검증_실패한_경로에서도_원문_sub가_로그에_노출되지_않는다() {
      // Given — 서명은 통과했으나 back-channel-logout 이벤트 클레임이 없는 토큰
      Map<String, Object> claims = new HashMap<>();
      claims.put("sub", SUBJECT);
      claims.put("iss", "http://keycloak/realms/test");
      // events 클레임 없음 — isLogoutToken() == false

      Jwt noEventJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(noEventJwt));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
    }

    @Test
    void 세션_무효화_중_오류가_발생해도_원문_JWT와_sub가_로그에_노출되지_않는다() {
      // Given — 서명 검증은 통과했지만 세션 저장소 삭제 단계에서 오류 발생
      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);

      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID))
          .thenReturn(Mono.error(new RuntimeException("session store unavailable")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
      // 오류 로그 자체는 남아야 함 (positive control)
      assertThat(messages).anyMatch(m -> m.contains("세션 무효화 중 오류"));
    }

    @Test
    void authentication이_null이어도_로그에_민감정보가_노출되지_않는다() {
      // When
      StepVerifier.create(handler.logout(mockWebFilterExchange(), null))
          .verifyComplete();

      // Then
      List<String> messages = formattedMessages();
      assertThat(messages).noneMatch(m -> m.contains(LOGOUT_TOKEN_JWT));
      assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
    }
  }
}
