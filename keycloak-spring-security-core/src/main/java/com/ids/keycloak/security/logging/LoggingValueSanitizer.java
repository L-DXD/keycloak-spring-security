package com.ids.keycloak.security.logging;

/**
 * 로그(MDC 등)에 넣기 전에 값의 개인정보·비밀을 가린다.
 * <p>
 * 기본은 {@link DefaultPiiMaskingSanitizer}. 이 타입의 빈을 올리면 그것을 쓰고, 가리지 않으려면
 * {@link NoOpLoggingValueSanitizer}를 빈으로 올린다. 로그에 민감한 값을 넣지 않는 것이 먼저이고, 가리기는 두 번째 방어선이다.
 */
@FunctionalInterface
public interface LoggingValueSanitizer {

    /**
     * @param key   MDC 키 (키마다 다르게 가릴 때 쓴다. 기본 구현은 보지 않는다)
     * @param value 원래 값 ({@code null} 가능)
     * @return 가린 값 ({@code null}이면 {@code null})
     */
    String sanitize(String key, String value);
}
