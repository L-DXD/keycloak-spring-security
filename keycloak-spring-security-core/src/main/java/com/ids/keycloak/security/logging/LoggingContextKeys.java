package com.ids.keycloak.security.logging;

/**
 * 라이브러리가 MDC에 넣는 키. v2와 같은 이름이다 (로그 형식·대시보드를 그대로 쓸 수 있게).
 */
public class LoggingContextKeys {

    // ===== 요청 (인증 전) =====

    /** 요청 추적 id ({@code X-Request-Id} 또는 새 UUID). */
    public static final String TRACE_ID = "traceId";
    /** HTTP 메서드. */
    public static final String HTTP_METHOD = "httpMethod";
    /** 요청 경로. */
    public static final String REQUEST_URI = "requestUri";
    /** 쿼리 문자열 (? 뺌, 디코딩·길이 제한·마스킹). 기본은 넣지 않는다. */
    public static final String QUERY_STRING = "queryString";
    /** 클라이언트 IP ({@code trusted-proxy-count} 기준). */
    public static final String CLIENT_IP = "clientIp";
    /** User-Agent (길이 제한·마스킹). */
    public static final String USER_AGENT = "userAgent";

    // ===== 응답 (요청 끝, 기본 끔) =====

    /** 응답 상태 코드. */
    public static final String STATUS = "status";
    /** 처리 시간 (밀리초). */
    public static final String DURATION_MS = "durationMs";

    // ===== 사용자 (인증 뒤) =====

    /** Keycloak 사용자 id ({@code sub}). */
    public static final String USER_ID = "userId";
    /** {@code preferred_username}. */
    public static final String USERNAME = "username";
    /** Keycloak 세션 id (액세스 토큰 {@code sid}). 앱의 sid 쿠키 값이 아니다. */
    public static final String SESSION_ID = "sessionId";

    protected LoggingContextKeys() {
    }
}
