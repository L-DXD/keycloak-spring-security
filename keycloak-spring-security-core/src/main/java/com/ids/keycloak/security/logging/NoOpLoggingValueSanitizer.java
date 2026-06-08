package com.ids.keycloak.security.logging;

/**
 * 마스킹을 수행하지 않고 값을 그대로 통과시키는 {@link LoggingValueSanitizer} 구현체.
 * <p>
 * PII 마스킹을 비활성화하려는 사용자가 명시적으로 빈으로 등록하여 기본
 * {@code DefaultPiiMaskingSanitizer}를 대체할 때 사용합니다.
 * </p>
 */
public class NoOpLoggingValueSanitizer implements LoggingValueSanitizer {

    @Override
    public String sanitize(String key, String value) {
        return value;
    }
}
