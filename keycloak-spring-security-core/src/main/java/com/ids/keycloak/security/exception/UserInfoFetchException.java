package com.ids.keycloak.security.exception;

public class UserInfoFetchException extends KeycloakSecurityException {

    public UserInfoFetchException() {
        super(ErrorCode.USERINFO_FETCH_FAILED);
    }

    public UserInfoFetchException(String message) {
        super(ErrorCode.USERINFO_FETCH_FAILED, message);
    }

    public UserInfoFetchException(String message, Throwable cause) {
        super(ErrorCode.USERINFO_FETCH_FAILED, message, cause);
    }
}
