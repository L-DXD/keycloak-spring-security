package com.ids.keycloak.security.exception;

public class ConfigurationException extends KeycloakSecurityException {

    public ConfigurationException() {
        super(ErrorCode.CONFIGURATION_ERROR);
    }

    public ConfigurationException(String message) {
        super(ErrorCode.CONFIGURATION_ERROR, message);
    }

    public ConfigurationException(String message, Throwable cause) {
        super(ErrorCode.CONFIGURATION_ERROR, message, cause);
    }
}