package com.ids.keycloak.security.exception;

public class AuthorityMappingException extends KeycloakSecurityException {

    public AuthorityMappingException() {
        super(ErrorCode.AUTHORITY_MAPPING_FAILED);
    }

    public AuthorityMappingException(String message) {
        super(ErrorCode.AUTHORITY_MAPPING_FAILED, message);
    }

    public AuthorityMappingException(String message, Throwable cause) {
        super(ErrorCode.AUTHORITY_MAPPING_FAILED, message, cause);
    }
}