package com.ids.keycloak.security.session;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

/**
 * WebFlux {@link WebSession} 기반 Keycloak 세션 데이터 관리자입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakSessionManager}를 Reactive로 포팅합니다.
 * WebSession은 Non-blocking 방식으로 접근하며, 데이터 자체는 동기적으로 읽고 씁니다.</p>
 *
 * <p>저장 데이터:
 * <ul>
 *   <li>Refresh Token — 토큰 갱신에 사용</li>
 *   <li>Keycloak Session ID(sid) — Back-Channel 로그아웃에 사용</li>
 * </ul>
 * </p>
 */
@Slf4j
public class ReactiveSessionManager {

  /** 세션에 Refresh Token을 저장하는 키 */
  public static final String REFRESH_TOKEN_ATTR = "KEYCLOAK_REFRESH_TOKEN";

  /** 세션에 Keycloak Session ID를 저장하는 키 */
  public static final String KEYCLOAK_SESSION_ID_ATTR = "KEYCLOAK_SESSION_ID";

  /**
   * WebSession에서 Refresh Token을 조회합니다.
   *
   * @param session WebSession
   * @return Refresh Token (Optional)
   */
  public Optional<String> getRefreshToken(WebSession session) {
    if (session == null) {
      return Optional.empty();
    }
    String refreshToken = session.getAttribute(REFRESH_TOKEN_ATTR);
    return Optional.ofNullable(refreshToken);
  }

  /**
   * WebSession에 Refresh Token을 저장합니다.
   *
   * @param session      WebSession
   * @param refreshToken 저장할 Refresh Token
   */
  public void saveRefreshToken(WebSession session, String refreshToken) {
    if (session == null || refreshToken == null) {
      log.warn("[ReactiveSessionManager] session 또는 refreshToken이 null입니다.");
      return;
    }
    session.getAttributes().put(REFRESH_TOKEN_ATTR, refreshToken);
    log.debug("[ReactiveSessionManager] Refresh Token 저장 완료.");
  }

  /**
   * WebSession에서 Refresh Token을 제거합니다.
   *
   * @param session WebSession
   */
  public void removeRefreshToken(WebSession session) {
    if (session == null) {
      return;
    }
    session.getAttributes().remove(REFRESH_TOKEN_ATTR);
    log.debug("[ReactiveSessionManager] Refresh Token 삭제 완료.");
  }

  /**
   * WebSession에 Keycloak Session ID(sid)를 저장합니다.
   *
   * @param session           WebSession
   * @param keycloakSessionId Keycloak sid 클레임 값
   */
  public void saveKeycloakSessionId(WebSession session, String keycloakSessionId) {
    if (session == null || keycloakSessionId == null) {
      return;
    }
    session.getAttributes().put(KEYCLOAK_SESSION_ID_ATTR, keycloakSessionId);
    log.debug("[ReactiveSessionManager] Keycloak Session ID 저장: {}", keycloakSessionId);
  }

  /**
   * WebSession에서 Keycloak Session ID를 조회합니다.
   *
   * @param session WebSession
   * @return Keycloak Session ID (Optional)
   */
  public Optional<String> getKeycloakSessionId(WebSession session) {
    if (session == null) {
      return Optional.empty();
    }
    String sid = session.getAttribute(KEYCLOAK_SESSION_ID_ATTR);
    return Optional.ofNullable(sid);
  }

  /**
   * WebSession에 Principal Name을 저장합니다.
   * Back-Channel 로그아웃 시 세션 검색에 사용됩니다.
   *
   * @param session       WebSession
   * @param principalName 사용자 식별자
   */
  public void savePrincipalName(WebSession session, String principalName) {
    if (session == null || principalName == null) {
      return;
    }
    session.getAttributes().put(
        FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, principalName);
    log.debug("[ReactiveSessionManager] Principal Name 저장: {}", principalName);
  }

  /**
   * WebSession을 무효화합니다.
   *
   * @param session WebSession
   * @return 완료를 나타내는 Mono
   */
  public Mono<Void> invalidateSession(WebSession session) {
    if (session == null) {
      log.debug("[ReactiveSessionManager] 무효화할 세션이 없습니다.");
      return Mono.empty();
    }
    String sessionId = session.getId();
    return session.invalidate()
        .doOnSuccess(v -> log.debug("[ReactiveSessionManager] 세션 무효화 완료. Session ID: {}", sessionId));
  }
}
