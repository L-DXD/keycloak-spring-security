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

    private static String safeUsername(String username) {
        return username != null ? username : "unknown";
    }
}
