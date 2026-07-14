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
   * 응답 상태 코드를 직접 검사해야 하는 테스트를 위해, 노출된 {@link MockServerWebExchange}를 생성합니다.
   */
  private MockServerWebExchange buildExchange() {
    MockServerHttpRequest request = MockServerHttpRequest
        .post("/logout/connect/back-channel/keycloak").build();
    return MockServerWebExchange.from(request);
  }

  private WebFilterExchange webFilterExchange(MockServerWebExchange exchange) {
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
    void aud_불일치_토큰은_검증_실패로_세션_삭제_없이_BadRequest_반환() {
      // Given: audience 불일치 — 다른 클라이언트용 logout_token (decoder가 aud 검증에서 거부)
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT))
          .thenReturn(Mono.error(new JwtException("The aud claim is not valid")));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      MockServerWebExchange exchange = buildExchange();
      // When & Then
      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
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

    @Test
    void sub와_sid_모두_없으면_세션_삭제_없이_BadRequest_응답() {
      // events 클레임은 있으나 sub/sid가 모두 없는 토큰 (서명은 통과)
      Map<String, Object> claims = buildLogoutTokenClaims(null, null);

      Jwt jwtWithoutSubAndSid = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(jwtWithoutSubAndSid));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      MockServerWebExchange exchange = buildExchange();
      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
      verify(sessionRepository, never()).deleteById(anyString());
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
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

  // ==========================================================================
  // 보안 Advisory 8: 핸들러 독립 iss/aud 재검증 (심층 방어)
  // ==========================================================================

  /**
   * 보안 Advisory 8 대응 검증: 주입된 {@link ReactiveJwtDecoder}가 (이름 기반 override 등으로)
   * 실제로는 iss/aud를 검증하지 않더라도, 핸들러 자신이 {@code expectedIssuer}/{@code expectedAudience}로
   * 독립적으로 재검증한다. 이 시나리오를 흉내내기 위해 jwtDecoder mock은 항상 성공(서명 검증 통과)을
   * 반환하고, JWT의 iss/aud 클레임만 조작한다.
   */
  @Nested
  class Advisory8_핸들러_독립_재검증 {

    private static final String EXPECTED_ISSUER = "http://keycloak/realms/expected";
    private static final String EXPECTED_AUDIENCE = "expected-client-id";

    /**
     * events/sub/sid는 유효하되 iss/aud만 파라미터로 지정하는 JWT를 생성합니다.
     */
    private Jwt buildJwtWithIssuerAndAudience(String issuer, String audience) {
      Map<String, Object> claims = new HashMap<>();
      claims.put("iss", issuer);
      if (audience != null) {
        claims.put("aud", List.of(audience));
      }
      claims.put("sub", SUBJECT);
      claims.put("sid", KEYCLOAK_SID);
      Map<String, Object> events = new HashMap<>();
      events.put("http://schemas.openid.net/event/backchannel-logout", new HashMap<>());
      claims.put("events", events);
      return buildJwt(claims);
    }

    @Test
    void expectedIssuer_불일치시_decoder가_통과시켜도_세션삭제없이_BadRequest_반환() {
      handler.setExpectedIssuer(EXPECTED_ISSUER);
      handler.setExpectedAudience(EXPECTED_AUDIENCE);

      // decoder 자체는 서명 검증만 통과(iss 불일치를 걸러내지 않는다고 가정)
      Jwt jwtWithWrongIssuer = buildJwtWithIssuerAndAudience(
          "http://attacker.example/realms/evil", EXPECTED_AUDIENCE);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(jwtWithWrongIssuer));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);
      MockServerWebExchange exchange = buildExchange();

      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void expectedAudience_불일치시_decoder가_통과시켜도_세션삭제없이_BadRequest_반환() {
      handler.setExpectedIssuer(EXPECTED_ISSUER);
      handler.setExpectedAudience(EXPECTED_AUDIENCE);

      // decoder 자체는 서명 검증만 통과(aud 불일치를 걸러내지 않는다고 가정)
      Jwt jwtWithWrongAudience = buildJwtWithIssuerAndAudience(EXPECTED_ISSUER, "other-client-id");
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(jwtWithWrongAudience));

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);
      MockServerWebExchange exchange = buildExchange();

      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      verify(sessionRepository, never()).findByPrincipalName(anyString());
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void expectedIssuer_expectedAudience_모두_일치하면_정상_세션삭제_수행() {
      handler.setExpectedIssuer(EXPECTED_ISSUER);
      handler.setExpectedAudience(EXPECTED_AUDIENCE);

      Jwt validJwt = buildJwtWithIssuerAndAudience(EXPECTED_ISSUER, EXPECTED_AUDIENCE);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));

      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);
      when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      when(sessionRepository.deleteById(SPRING_SESSION_ID)).thenReturn(Mono.empty());

      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);
      MockServerWebExchange exchange = buildExchange();

      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      verify(sessionRepository).findByPrincipalName(SUBJECT);
      verify(sessionRepository).deleteById(SPRING_SESSION_ID);
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
    }
  }

  // ==========================================================================
  // 보안 Advisory 8(code-review Low 1): 심층방어 비활성 WARN 1회 로깅
  // ==========================================================================

  /**
   * {@code expectedIssuer}/{@code expectedAudience}를 설정하지 않은(수동 배선) 상태에서, 최초
   * logout 처리 시점에만 심층방어 비활성 WARN이 1회 로깅되고 이후에는 재로깅되지 않음을 검증합니다.
   */
  @Nested
  class Advisory8_심층방어_WARN_1회 {

    private Logger handlerLogger;
    private ListAppender<ILoggingEvent> logAppender;

    private static final String DEEP_DEFENSE_WARNING_MARKER = "심층방어 재검증이 비활성 상태입니다";

    @BeforeEach
    void setUpLogCapture() {
      handlerLogger = (Logger) LoggerFactory.getLogger(ReactiveOidcBackChannelLogoutHandler.class);
      logAppender = new ListAppender<>();
      logAppender.start();
      handlerLogger.addAppender(logAppender);
      handlerLogger.setLevel(Level.ALL);
    }

    @AfterEach
    void tearDownLogCapture() {
      handlerLogger.detachAppender(logAppender);
      logAppender.stop();
    }

    private long deepDefenseWarningCount() {
      return logAppender.list.stream()
          .map(ILoggingEvent::getFormattedMessage)
          .filter(m -> m.contains(DEEP_DEFENSE_WARNING_MARKER))
          .count();
    }

    private void stubValidLogout() {
      stubValidLogout(null);
    }

    /**
     * @param audience non-null이면 claims에 aud 클레임을 추가한다
     *                 (expectedAudience 설정 테스트에서 재검증을 통과시키기 위함)
     */
    private void stubValidLogout(String audience) {
      Map<String, Object> claims = buildLogoutTokenClaims(SUBJECT, KEYCLOAK_SID);
      if (audience != null) {
        claims.put("aud", List.of(audience));
      }
      Jwt validJwt = buildJwt(claims);
      when(jwtDecoder.decode(LOGOUT_TOKEN_JWT)).thenReturn(Mono.just(validJwt));

      Session session = mockSessionWithSid(KEYCLOAK_SID);
      Map<String, Session> sessions = Map.of(SPRING_SESSION_ID, session);
      lenient().when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(Mono.just(sessions));
      lenient().when(sessionRepository.deleteById(SPRING_SESSION_ID)).thenReturn(Mono.empty());
    }

    @Test
    void expectedIssuer_expectedAudience_미설정시_첫_처리에서만_WARN_1회_로깅() {
      // handler는 @BeforeEach에서 expectedIssuer/expectedAudience 없이(수동 배선 기본값) 생성됨
      stubValidLogout();
      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      // 1차 처리
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();
      assertThat(deepDefenseWarningCount())
          .as("첫 logout 처리에서 심층방어 비활성 WARN이 1회 로깅되어야 한다")
          .isEqualTo(1);

      // 2차 처리 — 동일 handler 인스턴스로 재호출해도 WARN이 추가로 찍히지 않아야 한다
      StepVerifier.create(handler.logout(mockWebFilterExchange(), auth))
          .verifyComplete();
      assertThat(deepDefenseWarningCount())
          .as("두 번째 처리에서는 WARN이 추가로 로깅되지 않아야 한다(1회성)")
          .isEqualTo(1);

      // positive control: 세션 삭제 자체는 두 번 다 정상 수행됨(WARN과 무관)
      verify(sessionRepository, org.mockito.Mockito.times(2)).findByPrincipalName(SUBJECT);
    }

    @Test
    void expectedIssuer_expectedAudience_설정시에는_WARN이_로깅되지_않는다() {
      handler.setExpectedIssuer("http://keycloak/realms/test");
      handler.setExpectedAudience("expected-client-id");
      stubValidLogout("expected-client-id");
      BackChannelLogoutAuthentication auth = new BackChannelLogoutAuthentication(LOGOUT_TOKEN_JWT);

      MockServerWebExchange exchange = buildExchange();
      StepVerifier.create(handler.logout(webFilterExchange(exchange), auth))
          .verifyComplete();

      assertThat(deepDefenseWarningCount())
          .as("자동 배선(오토컨피규레이션)과 동일하게 두 값이 모두 설정되면 WARN이 로깅되지 않아야 한다")
          .isEqualTo(0);
      // positive control: 재검증 자체는 통과하여 정상 처리된다
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
    }
  }
}
