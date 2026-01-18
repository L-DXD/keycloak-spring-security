package com.ids.keycloak.security.exception;

public enum ErrorCode {

    // 401 Unauthorized
    REFRESH_TOKEN_NOT_FOUND("REFRESH_TOKEN_NOT_FOUND", 401, "요청에서 리프레시 토큰을 찾을 수 없습니다."),
    AUTHENTICATION_FAILED("AUTHENTICATION_FAILED", 401, "유효하지 않은 자격 증명 또는 토큰으로 인해 인증에 실패했습니다."),
    AUTHENTICATION_REQUIRED("AUTHENTICATION_REQUIRED", 401, "이 리소스에 접근하려면 완전한 인증이 필요합니다."),
    TOKEN_EXPIRED("TOKEN_EXPIRED", 401, "토큰이 만료되었습니다."),
    INTROSPECTION_FAILED("INTROSPECTION_FAILED", 401, "토큰 온라인 검증에 실패했습니다."),

    // 403 Forbidden
    ACCESS_DENIED("ACCESS_DENIED", 403, "이 리소스에 접근할 권한이 없습니다."),

    // 500 Internal Server Error
    AUTHORITY_MAPPING_FAILED("AUTHORITY_MAPPING_FAILED", 500, "토큰으로부터 권한을 매핑하는 데 실패했습니다."),
    CONFIGURATION_ERROR("CONFIGURATION_ERROR", 500, "보안 설정 중 구성 오류가 발생했습니다.");

    private final String code;
    private final int httpStatus;
    private final String defaultMessage;

    ErrorCode(String code, int httpStatus, String defaultMessage) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public String getCode() {
        return code;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
