package com.ids.keycloak.security.error;

/**
 * 라이브러리가 내는 오류 응답 코드. 응답 본문은 {@code {"code": ..., "message": ...}} (v2와 같은 모양).
 */
public enum KeycloakErrorCode {

    /** 로그인이 필요하다 (쿠키 없음, 세션 끝남). 본문에 로그인 주소가 같이 간다. */
    AUTHENTICATION_REQUIRED(401, "로그인이 필요합니다."),
    /** 로그인은 했지만 권한이 없다. */
    ACCESS_DENIED(403, "이 리소스에 접근할 권한이 없습니다."),
    /** Keycloak(JWKS, 토큰 갱신)에 닿지 못했다. 세션은 그대로 두고 다시 시도하게 한다. */
    KEYCLOAK_UNAVAILABLE(503, "인증 서버에 연결할 수 없습니다. 잠시 뒤 다시 시도하세요.");

    private final int status;
    private final String message;

    KeycloakErrorCode(int status, String message) {
        this.status = status;
        this.message = message;
    }

    /** HTTP 상태 코드. */
    public int status() {
        return status;
    }

    /** 기본 메시지. */
    public String message() {
        return message;
    }
}
