package com.ids.keycloak.security.exception;

/**
 * 토큰이 만료되었을 때 발생하는 예외입니다.
 * 이 예외가 발생하면 Refresh Token을 사용한 토큰 재발급을 시도합니다.
 */
public class TokenExpiredException extends KeycloakSecurityException {

    public TokenExpiredException() {
        super(ErrorCode.TOKEN_EXPIRED);
    }

    public TokenExpiredException(String message) {
        super(ErrorCode.TOKEN_EXPIRED, message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_EXPIRED, message, cause);
    }
}
