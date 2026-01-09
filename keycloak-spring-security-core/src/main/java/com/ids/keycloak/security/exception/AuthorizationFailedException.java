package com.ids.keycloak.security.exception;

public class AuthorizationFailedException extends KeycloakSecurityException {

    public AuthorizationFailedException() {
        super(ErrorCode.ACCESS_DENIED);
    }

    public AuthorizationFailedException(String message) {
        super(ErrorCode.ACCESS_DENIED, message);
    }

    public AuthorizationFailedException(String message, Throwable cause) {
        super(ErrorCode.ACCESS_DENIED, message, cause);
    }
}