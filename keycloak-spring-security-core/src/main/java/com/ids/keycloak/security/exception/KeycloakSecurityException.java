package com.ids.keycloak.security.exception;

public class KeycloakSecurityException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * 기본 메시지를 사용하는 생성자
     * @param errorCode ErrorCode Enum
     */
    public KeycloakSecurityException(ErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    /**
     * 기본 메시지를 사용하는 생성자 (cause 포함)
     * @param errorCode ErrorCode Enum
     * @param cause 원인 예외
     */
    public KeycloakSecurityException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getDefaultMessage(), cause);
        this.errorCode = errorCode;
    }

    /**
     * 메시지를 직접 지정하는 생성자
     * @param errorCode ErrorCode Enum
     * @param message 직접 지정할 메시지
     */
    public KeycloakSecurityException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    /**
     * 메시지를 직접 지정하는 생성자 (cause 포함)
     * @param errorCode ErrorCode Enum
     * @param message 직접 지정할 메시지
     * @param cause 원인 예외
     */
    public KeycloakSecurityException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}