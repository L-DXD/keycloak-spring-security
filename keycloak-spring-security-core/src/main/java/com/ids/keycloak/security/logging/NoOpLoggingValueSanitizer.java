package com.ids.keycloak.security.logging;

/** 가리지 않는다. 빈으로 올리면 기본 마스킹을 끈다. */
public class NoOpLoggingValueSanitizer implements LoggingValueSanitizer {

    @Override
    public String sanitize(String key, String value) {
        return value;
    }
}
