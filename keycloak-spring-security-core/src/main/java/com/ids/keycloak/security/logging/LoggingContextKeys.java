package com.ids.keycloak.security.logging;

/**
 * 라이브러리 전반에서 사용하는 표준 MDC 키를 정의합니다.
 */
public final class LoggingContextKeys {

    private LoggingContextKeys() {}

    // ===== 요청 메타데이터 (인증 전 설정) =====

    /** 요청 추적 ID (X-Request-Id 또는 자동 생성) */
    public static final String TRACE_ID = "traceId";

    /** HTTP 메서드 (GET, POST, PUT, DELETE 등) */
    public static final String HTTP_METHOD = "httpMethod";

    /** 요청 URI */
    public static final String REQUEST_URI = "requestUri";

    /** 쿼리 스트링 (? 제외) */
    public static final String QUERY_STRING = "queryString";

    /** 클라이언트 IP 주소 */
    public static final String CLIENT_IP = "clientIp";

    // ===== 인증 정보 (인증 후 설정) =====

    /** 인증된 사용자 ID (Keycloak sub claim) */
    public static final String USER_ID = "userId";

    /** 인증된 사용자 이름 (preferred_username) */
    public static final String USERNAME = "username";

    /** Keycloak 세션 ID (sid claim) */
    public static final String SESSION_ID = "sessionId";
}