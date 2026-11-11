package com.ids.keycloak.security.web.refresh;

import java.io.Serial;

/**
 * Keycloak 토큰 주소 호출 실패.
 * <ul>
 *   <li>{@link #isInvalidGrant()}: Keycloak이 리프레시 토큰을 거절했다({@code invalid_grant}: 세션 끝남, 계정 비활성화 등). 세션을 끝낸다</li>
 *   <li>그 밖: 연결 실패, 5xx, client 인증 실패 등. 사용자 탓이 아니므로 세션은 두고 503</li>
 * </ul>
 */
public class KeycloakTokenException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String errorCode;

    public KeycloakTokenException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /** OAuth2 오류 코드 (예: {@code invalid_grant}). 연결 실패면 {@code invalid_token_response}. */
    public String errorCode() {
        return errorCode;
    }

    public boolean isInvalidGrant() {
        return "invalid_grant".equals(errorCode);
    }
}
