package com.ids.keycloak.security.ratelimit;

import lombok.extern.slf4j.Slf4j;

/**
 * 인증 이벤트를 표준 포맷으로 로깅하는 유틸리티 클래스입니다.
 *
 * <p>servlet 모듈의 {@code AuthenticationEventLogger}와 동일한 상수/메서드를 제공합니다.
 * WebFlux 모듈에서 재정의하여 core 의존성 없이 독립적으로 사용합니다.</p>
 */
@Slf4j
public final class AuthenticationEventLogger {

  public static final String METHOD_OIDC_COOKIE = "OIDC_COOKIE";
  public static final String METHOD_BASIC = "BASIC";
  public static final String METHOD_TOKEN_API = "TOKEN_API";
  public static final String METHOD_BEARER = "BEARER";

  private AuthenticationEventLogger() {
  }

  public static void logSuccess(String method, String clientIp, String username) {
    log.info("[AuthEvent] SUCCESS method={} clientIp={} username={}", method, clientIp, username);
  }

  public static void logFailure(String method, String clientIp, String username, String reason) {
    log.warn("[AuthEvent] FAILURE method={} clientIp={} username={} reason={}", method, clientIp, username, reason);
  }

  public static void logSkipped(String method, String clientIp, String reason) {
    log.debug("[AuthEvent] SKIPPED method={} clientIp={} reason={}", method, clientIp, reason);
  }

  public static void logNoSession(String method, String clientIp) {
    log.debug("[AuthEvent] NO_SESSION method={} clientIp={}", method, clientIp);
  }

  public static void logRateLimited(String method, String clientIp, String username) {
    log.warn("[AuthEvent] RATE_LIMITED method={} clientIp={} username={}", method, clientIp, username);
  }
}
