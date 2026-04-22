package com.ids.keycloak.security.ratelimit;

import lombok.extern.slf4j.Slf4j;

/**
 * 인증 이벤트를 구조화된 형식으로 로깅하는 유틸리티 클래스입니다.
 * <p>
 * 보안 감사(audit) 및 모니터링을 위해 인증 시도의 성공/실패/차단 이력을 기록합니다.
 * ELK/Grafana 등에서 파싱 가능한 구조화된 로그 형식을 사용합니다.
 * </p>
 * <p>
 * 로그 형식:
 * <pre>
 * [AUTH] result=SUCCESS method=BASIC ip=192.168.1.1 username=test
 * [AUTH] result=FAILURE method=TOKEN_API ip=10.0.0.5 username=admin reason=invalid_credentials
 * [AUTH] result=RATE_LIMITED method=TOKEN_API ip=10.0.0.5 username=admin reason=rate_limit_exceeded
 * </pre>
 * </p>
 * <p>
 * 로그 레벨: 성공은 INFO, 실패와 차단은 WARN
 * </p>
 */
@Slf4j
public final class AuthenticationEventLogger {

    private AuthenticationEventLogger() {
        // 유틸리티 클래스
    }

    /**
     * 인증 방식 상수
     */
    public static final String METHOD_BASIC = "BASIC";
    public static final String METHOD_TOKEN_API = "TOKEN_API";
    public static final String METHOD_BEARER_TOKEN = "BEARER_TOKEN";
    public static final String METHOD_OIDC_COOKIE = "OIDC_COOKIE";

    /**
     * 인증 성공을 로깅합니다. (INFO 레벨)
     *
     * @param method   인증 방식 (BASIC, TOKEN_API, BEARER_TOKEN, OIDC_COOKIE)
     * @param ip       클라이언트 IP
     * @param username 사용자명
     */
    public static void logSuccess(String method, String ip, String username) {
        log.info("[AUTH] result=SUCCESS method={} ip={} username={}",
            method, ip, safeUsername(username));
    }

    /**
     * 인증 실패를 로깅합니다. (WARN 레벨)
     *
     * @param method   인증 방식
     * @param ip       클라이언트 IP
     * @param username 사용자명
     * @param reason   실패 사유
     */
    public static void logFailure(String method, String ip, String username, String reason) {
        log.warn("[AUTH] result=FAILURE method={} ip={} username={} reason={}",
            method, ip, safeUsername(username), reason);
    }

    /**
     * Rate Limit 차단을 로깅합니다. (WARN 레벨)
     *
     * @param method   인증 방식
     * @param ip       클라이언트 IP
     * @param username 사용자명
     */
    public static void logRateLimited(String method, String ip, String username) {
        log.warn("[AUTH] result=RATE_LIMITED method={} ip={} username={} reason=rate_limit_exceeded",
            method, ip, safeUsername(username));
    }

    /**
     * Stateless 인증 경로(Bearer/Basic/Credential-Login)에서 필터를 건너뛰는 이벤트를 로깅합니다. (INFO 레벨)
     * <p>
     * rate-limit 카운터 증가 없이 관찰 목적으로만 기록됩니다.
     * </p>
     *
     * @param method 인증 방식 (BEARER, BASIC, CREDENTIAL_LOGIN 등)
     * @param ip     클라이언트 IP
     * @param reason 스킵 사유
     */
    public static void logSkipped(String method, String ip, String reason) {
        log.info("[AUTH] result=SKIPPED method={} ip={} username=unknown reason={}",
            method, ip, reason);
    }

    /**
     * OIDC 쿠키 흐름에서 HTTP Session이 없는 상태를 로깅합니다. (DEBUG 레벨)
     * <p>
     * 정상적인 비로그인 상태이므로 감사 통계 집계 및 rate-limit 카운터에서 제외됩니다.
     * </p>
     *
     * @param method 인증 방식 (OIDC_COOKIE)
     * @param ip     클라이언트 IP
     */
    public static void logNoSession(String method, String ip) {
        log.debug("[AUTH] result=NO_SESSION method={} ip={} username=unknown reason=session_not_found",
            method, ip);
    }

    private static String safeUsername(String username) {
        return username != null ? username : "unknown";
    }
}
