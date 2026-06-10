package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakLogoutToken;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import java.util.Collections;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.session.ReactiveFindByIndexNameSessionRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * OIDC Back-Channel Logout 요청을 처리하는 Reactive {@link ServerLogoutHandler} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code OidcBackChannelSessionLogoutHandler}를 Reactive로 포팅합니다.
 * Keycloak이 {@code /logout/connect/back-channel/keycloak} 엔드포인트로 POST 요청을 보낼 때
 * {@code logout_token} JWT를 <b>서명 검증</b>한 뒤 sub/sid에 해당하는 세션을
 * {@link ReactiveFindByIndexNameSessionRepository}로 무효화합니다.</p>
 *
 * <p><b>C-1 보안 수정 (Critical):</b>
 * 이전 구현에서는 {@code JwtUtil.parseClaimsWithoutValidation()}으로 서명 검증 없이
 * 클레임을 추출하여 세션을 삭제할 수 있었습니다.
 * 현재 구현은 {@link ReactiveJwtDecoder}(Keycloak JWKS 기반)를 통해 아래를 모두 검증합니다:
 * <ul>
 *   <li>RS256/ES256 서명 (JWKS 공개키로 검증)</li>
 *   <li>{@code iss} (issuer) 클레임</li>
 *   <li>{@code aud} (audience) 클레임 — 클라이언트 ID와 일치 여부</li>
 *   <li>{@code events} 클레임 — back-channel logout 이벤트 URI 포함 여부</li>
 * </ul>
 * 위 검증을 통과한 토큰에 대해서만 sub/sid로 세션을 삭제합니다.</p>
 *
 * <p><b>처리 흐름:</b>
 * <ol>
 *   <li>요청 폼 파라미터에서 {@code logout_token} 추출</li>
 *   <li>{@link ReactiveJwtDecoder}로 서명·iss·aud 검증 (실패 시 400 Bad Request 즉시 반환)</li>
 *   <li>검증된 JWT에서 {@link KeycloakLogoutToken} 생성 및 {@code events} 클레임 검증</li>
 *   <li>sid 있음 → 해당 Keycloak SID 속성을 가진 세션만 삭제</li>
 *   <li>sid 없음, sub 있음 → 해당 사용자의 모든 세션 삭제</li>
 *   <li>성공: 200 OK, 실패: 400 Bad Request 응답</li>
 * </ol>
 * </p>
 *
 * <p><b>의존성 조건:</b> {@code ReactiveFindByIndexNameSessionRepository}는 Spring Session Reactive
 * (spring-session-core)에 포함됩니다. 사용자가 Redis Reactive 등을 사용할 때만 활성화됩니다.
 * {@code @ConditionalOnBean(ReactiveFindByIndexNameSessionRepository.class)}로 조건부 등록하세요.</p>
 *
 * @see ReactiveBackChannelLogoutEndpointFilter
 */
@Slf4j
public class ReactiveOidcBackChannelLogoutHandler implements ServerLogoutHandler {

  /** 세션에 저장된 Keycloak Session ID 속성 키 (ReactiveSessionManager와 동일) */
  public static final String KEYCLOAK_SESSION_ID_ATTR = ReactiveSessionManager.KEYCLOAK_SESSION_ID_ATTR;

  private final ReactiveFindByIndexNameSessionRepository<? extends Session> findByIndexNameRepo;
  private final ReactiveSessionRepository<? extends Session> reactiveRepo;
  private final ReactiveJwtDecoder jwtDecoder;

  /**
   * 서명 검증용 {@link ReactiveJwtDecoder}를 주입받는 생성자입니다.
   *
   * <p>{@link ReactiveJwtDecoder}는 Keycloak JWKS 엔드포인트를 기반으로 생성해야 합니다:
   * <pre>
   * ReactiveJwtDecoders.fromIssuerLocation("https://keycloak.example.com/realms/myrealm")
   * </pre>
   * 또는 jwk-set-uri 기반:
   * <pre>
   * NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build()
   * </pre>
   * </p>
   *
   * @param sessionRepository {@link ReactiveFindByIndexNameSessionRepository}이자
   *                          {@link ReactiveSessionRepository}이기도 한 구현체
   *                          (예: Spring Session Redis Reactive)
   * @param jwtDecoder        Keycloak JWKS 기반 {@link ReactiveJwtDecoder} — 서명/iss/aud 검증용
   */
  @SuppressWarnings("unchecked")
  public ReactiveOidcBackChannelLogoutHandler(
      ReactiveFindByIndexNameSessionRepository<? extends Session> sessionRepository,
      ReactiveJwtDecoder jwtDecoder) {
    this.findByIndexNameRepo = sessionRepository;
    // 실제 구현체(예: ReactiveRedisIndexedSessionRepository)는 ReactiveSessionRepository도 구현한다.
    // 캐스팅 실패 시 ClassCastException이 발생하며, 이는 설정 오류를 의미한다.
    this.reactiveRepo = (ReactiveSessionRepository<? extends Session>) sessionRepository;
    this.jwtDecoder = jwtDecoder;
  }

  /**
   * Back-Channel logout_token을 <b>서명 검증</b> 후 해당 세션을 무효화합니다.
   *
   * <p>이 핸들러는 {@link ReactiveBackChannelLogoutEndpointFilter}에 의해 호출됩니다.
   * Authentication principal에 logout_token JWT 문자열이 담겨있습니다.</p>
   *
   * <p><b>C-1 수정:</b> 서명 검증을 통과하지 못한 토큰은 세션 삭제를 수행하지 않고
   * 즉시 400 Bad Request를 반환합니다.</p>
   */
  @Override
  public Mono<Void> logout(WebFilterExchange webFilterExchange, Authentication authentication) {
    if (authentication == null) {
      log.debug("[BackChannelLogoutHandler] Authentication이 null — 처리 스킵");
      return respondBadRequest(webFilterExchange.getExchange(), "Authentication is null");
    }

    String logoutTokenJwt = extractLogoutTokenJwt(authentication);
    if (logoutTokenJwt == null || logoutTokenJwt.isBlank()) {
      log.warn("[BackChannelLogoutHandler] logout_token을 추출할 수 없음");
      return respondBadRequest(webFilterExchange.getExchange(), "Missing logout_token");
    }

    // C-1 핵심 수정: ReactiveJwtDecoder로 서명 + iss + aud 검증
    return jwtDecoder.decode(logoutTokenJwt)
        .flatMap(jwt -> processVerifiedLogoutToken(webFilterExchange.getExchange(), jwt))
        .onErrorResume(e -> {
          // JwtException — 서명 불일치, 만료, iss/aud 불일치 등 모든 검증 실패
          log.warn("[BackChannelLogoutHandler] logout_token 서명/검증 실패: {}", e.getMessage());
          return respondBadRequest(webFilterExchange.getExchange(),
              "logout_token verification failed: " + e.getMessage());
        });
  }

  /**
   * 서명 검증을 통과한 JWT를 처리합니다.
   *
   * <p>{@code events} 클레임과 {@code sub}/{@code sid} 유효성을 추가로 확인한 뒤 세션을 삭제합니다.</p>
   */
  private Mono<Void> processVerifiedLogoutToken(ServerWebExchange exchange, Jwt jwt) {
    Map<String, Object> claims = jwt.getClaims();
    if (claims == null) {
      return respondBadRequest(exchange, "Empty claims in logout_token");
    }

    KeycloakLogoutToken logoutToken = new KeycloakLogoutToken(claims);
    if (!logoutToken.isLogoutToken()) {
      log.warn("[BackChannelLogoutHandler] 유효한 Back-Channel Logout 이벤트가 없음 — events 클레임 누락");
      return respondBadRequest(exchange, "Not a valid logout token: missing backchannel-logout event");
    }

    String subject = logoutToken.getSubject();
    String keycloakSessionId = logoutToken.getSessionId();

    log.debug("[BackChannelLogoutHandler] 서명 검증 완료. Logout Token - sub={}, sid={}", subject,
        keycloakSessionId);

    if (subject == null && keycloakSessionId == null) {
      log.warn("[BackChannelLogoutHandler] sub와 sid 모두 없음 — 처리 스킵");
      return respondBadRequest(exchange, "logout_token has neither sub nor sid");
    }

    Mono<Void> revokeAction;
    if (keycloakSessionId != null && subject != null) {
      revokeAction = revokeSessionByKeycloakSid(subject, keycloakSessionId);
    } else if (subject != null) {
      revokeAction = revokeAllUserSessions(subject);
    } else {
      // sid만 있고 sub가 없는 경우는 spec상 드물지만 fallback
      log.warn("[BackChannelLogoutHandler] sub 없이 sid만 존재 — subject 없이 처리 불가");
      return respondBadRequest(exchange, "logout_token missing sub");
    }

    return revokeAction
        .then(respondOk(exchange))
        .onErrorResume(e -> {
          log.error("[BackChannelLogoutHandler] 세션 무효화 중 오류: {}", e.getMessage(), e);
          return respondBadRequest(exchange, "Session revocation failed");
        });
  }

  /**
   * Authentication 객체에서 logout_token JWT 문자열을 추출합니다.
   *
   * <p>credentials에서 우선 추출합니다.
   * {@link BackChannelLogoutAuthentication}은 credentials에 JWT를 담고
   * principal에는 고정 문자열("back-channel-logout")을 담으므로
   * credentials를 먼저 확인하는 것이 중요합니다.</p>
   */
  private String extractLogoutTokenJwt(Authentication authentication) {
    Object credentials = authentication.getCredentials();
    if (credentials instanceof String jwt && !jwt.isBlank()) {
      return jwt;
    }
    // credentials가 null 또는 비어있으면 details에서 시도 (principal은 고정값일 수 있으므로 제외)
    if (authentication.getDetails() instanceof String jwt && !jwt.isBlank()) {
      return jwt;
    }
    return null;
  }

  /**
   * 특정 Keycloak SID(sid)에 해당하는 세션만 삭제합니다.
   * subject 기준으로 세션 목록을 조회한 뒤 KEYCLOAK_SESSION_ID_ATTR 속성을 비교합니다.
   */
  private Mono<Void> revokeSessionByKeycloakSid(String subject, String keycloakSessionId) {
    return findByIndexNameRepo
        .findByPrincipalName(subject)
        .flatMapMany(sessions -> Flux.fromIterable(sessions.entrySet()))
        .filter(entry -> keycloakSessionId.equals(
            entry.getValue().getAttribute(KEYCLOAK_SESSION_ID_ATTR)))
        .flatMap(entry -> {
          log.debug(
              "[BackChannelLogoutHandler] 세션 삭제 - Spring Session ID: {}, Keycloak SID: {}",
              entry.getKey(), keycloakSessionId);
          return reactiveRepo.deleteById(entry.getKey())
              .doOnSuccess(v -> log.info(
                  "[BackChannelLogoutHandler] Keycloak SID '{}' 세션 폐기 완료",
                  keycloakSessionId));
        })
        .then();
  }

  /**
   * 주어진 subject에 해당하는 모든 세션을 삭제합니다.
   */
  private Mono<Void> revokeAllUserSessions(String subject) {
    return findByIndexNameRepo
        .findByPrincipalName(subject)
        .flatMapMany(sessions -> Flux.fromIterable(sessions.entrySet()))
        .flatMap(entry -> {
          log.debug("[BackChannelLogoutHandler] 세션 삭제 - Session ID: {}", entry.getKey());
          return reactiveRepo.deleteById(entry.getKey());
        })
        .then()
        .doOnSuccess(v -> log.info(
            "[BackChannelLogoutHandler] subject '{}' 모든 세션 폐기 완료", subject));
  }

  private Mono<Void> respondOk(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.OK);
    return exchange.getResponse().setComplete();
  }

  private Mono<Void> respondBadRequest(ServerWebExchange exchange, String reason) {
    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.BAD_REQUEST);
    exchange.getResponse().getHeaders().setContentType(MediaType.TEXT_PLAIN);
    byte[] bytes = reason.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    org.springframework.core.io.buffer.DataBuffer buffer =
        exchange.getResponse().bufferFactory().wrap(bytes);
    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
