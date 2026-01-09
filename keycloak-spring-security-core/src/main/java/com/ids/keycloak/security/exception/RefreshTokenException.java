package com.ids.keycloak.security.exception;

public class RefreshTokenException extends KeycloakSecurityException {

    public RefreshTokenException() {
        super(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
    }

    public RefreshTokenException(String message) {
        super(ErrorCode.REFRESH_TOKEN_NOT_FOUND, message);
    }
    
    public RefreshTokenException(String message, Throwable cause) {
        super(ErrorCode.REFRESH_TOKEN_NOT_FOUND, message, cause);
    }
}
