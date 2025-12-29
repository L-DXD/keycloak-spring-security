package com.ids.keycloak.security.exception;

public class AuthenticationRequiredException extends KeycloakSecurityException {

    public AuthenticationRequiredException() {
        super(ErrorCode.AUTHENTICATION_REQUIRED);
    }

    public AuthenticationRequiredException(String message) {
        super(ErrorCode.AUTHENTICATION_REQUIRED, message);
    }

    public AuthenticationRequiredException(String message, Throwable cause) {
        super(ErrorCode.AUTHENTICATION_REQUIRED, message, cause);
    }
}