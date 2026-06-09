package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakLogoutToken;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.JwtUtil;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
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
 * {@code logout_token} JWT를 파싱하여 sub/sid에 해당하는 세션을 {@link ReactiveFindByIndexNameSessionRepository}로 무효화합니다.</p>
 *
 * <p><b>처리 흐름:</b>
 * <ol>
 *   <li>요청 폼 파라미터에서 {@code logout_token} 추출</li>
 *   <li>JWT 파싱 → {@link KeycloakLogoutToken} 생성 및 유효성 검증</li>
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

  /**
   * @param sessionRepository {@link ReactiveFindByIndexNameSessionRepository}이자
   *                          {@link ReactiveSessionRepository}이기도 한 구현체
   *                          (예: Spring Session Redis Reactive)
   */
  @SuppressWarnings("unchecked")
  public ReactiveOidcBackChannelLogoutHandler(
      ReactiveFindByIndexNameSessionRepository<? extends Session> sessionRepository) {
    this.findByIndexNameRepo = sessionRepository;
    // 실제 구현체(예: ReactiveRedisIndexedSessionRepository)는 ReactiveSessionRepository도 구현한다.
    // 캐스팅 실패 시 ClassCastException이 발생하며, 이는 설정 오류를 의미한다.
    this.reactiveRepo = (ReactiveSessionRepository<? extends Session>) sessionRepository;
  }

  /**
   * Back-Channel logout_token을 파싱하여 해당 세션을 무효화합니다.
   *
   * <p>이 핸들러는 {@link ReactiveBackChannelLogoutEndpointFilter}에 의해 호출됩니다.
   * Authentication principal에 logout_token JWT 문자열이 담겨있습니다.</p>
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

    Map<String, Object> claims = JwtUtil.parseClaimsWithoutValidation(logoutTokenJwt);
    if (claims.isEmpty()) {
      log.warn("[BackChannelLogoutHandler] logout_token JWT 파싱 실패");
      return respondBadRequest(webFilterExchange.getExchange(), "Invalid logout_token JWT");
    }

    KeycloakLogoutToken logoutToken = new KeycloakLogoutToken(claims);
    if (!logoutToken.isLogoutToken()) {
      log.warn("[BackChannelLogoutHandler] 유효한 Back-Channel Logout 이벤트가 없음");
      return respondBadRequest(webFilterExchange.getExchange(), "Not a valid logout token");
    }

    String subject = logoutToken.getSubject();
    String keycloakSessionId = logoutToken.getSessionId();

    log.debug("[BackChannelLogoutHandler] Logout Token - sub={}, sid={}", subject, keycloakSessionId);

    if (subject == null && keycloakSessionId == null) {
      log.warn("[BackChannelLogoutHandler] sub와 sid 모두 없음 — 처리 스킵");
      return respondBadRequest(webFilterExchange.getExchange(), "logout_token has neither sub nor sid");
    }

    Mono<Void> revokeAction;
    if (keycloakSessionId != null && subject != null) {
      revokeAction = revokeSessionByKeycloakSid(subject, keycloakSessionId);
    } else if (subject != null) {
      revokeAction = revokeAllUserSessions(subject);
    } else {
      // sid만 있고 sub가 없는 경우는 spec상 드물지만 fallback
      log.warn("[BackChannelLogoutHandler] sub 없이 sid만 존재 — subject 없이 처리 불가");
      return respondBadRequest(webFilterExchange.getExchange(), "logout_token missing sub");
    }

    return revokeAction
        .then(respondOk(webFilterExchange.getExchange()))
        .onErrorResume(e -> {
          log.error("[BackChannelLogoutHandler] 세션 무효화 중 오류: {}", e.getMessage(), e);
          return respondBadRequest(webFilterExchange.getExchange(), "Session revocation failed");
        });
  }

  /**
   * Authentication 객체에서 logout_token JWT 문자열을 추출합니다.
   * principal 또는 credentials에서 String을 탐색합니다.
   */
  private String extractLogoutTokenJwt(Authentication authentication) {
    if (authentication.getCredentials() instanceof String jwt) {
      return jwt;
    }
    if (authentication.getPrincipal() instanceof String jwt) {
      return jwt;
    }
    if (authentication.getDetails() instanceof String jwt) {
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
        .filter(entry -> keycloakSessionId.equals(entry.getValue().getAttribute(KEYCLOAK_SESSION_ID_ATTR)))
        .flatMap(entry -> {
          log.debug("[BackChannelLogoutHandler] 세션 삭제 - Spring Session ID: {}, Keycloak SID: {}",
              entry.getKey(), keycloakSessionId);
          return reactiveRepo.deleteById(entry.getKey())
              .doOnSuccess(v -> log.info(
                  "[BackChannelLogoutHandler] Keycloak SID '{}' 세션 폐기 완료", keycloakSessionId));
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
        .doOnSuccess(v -> log.info("[BackChannelLogoutHandler] subject '{}' 모든 세션 폐기 완료", subject));
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
