package com.ids.keycloak.security.exception;

/**
 * Keycloak Introspect API를 통한 토큰 온라인 검증에 실패했을 때 발생하는 예외입니다.
 * 이 예외가 발생하면 Refresh Token을 사용한 토큰 재발급을 시도합니다.
 */
public class IntrospectionFailedException extends KeycloakSecurityException {

    public IntrospectionFailedException() {
        super(ErrorCode.INTROSPECTION_FAILED);
    }

    public IntrospectionFailedException(String message) {
        super(ErrorCode.INTROSPECTION_FAILED, message);
    }

    public IntrospectionFailedException(String message, Throwable cause) {
        super(ErrorCode.INTROSPECTION_FAILED, message, cause);
    }
}
