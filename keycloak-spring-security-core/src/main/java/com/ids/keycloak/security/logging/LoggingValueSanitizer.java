package com.ids.keycloak.security.logging;

/**
 * 로그(MDC 등)에 기록되기 전에 값에서 민감정보(PII/시크릿)를 정제(마스킹)하는 SPI.
 * <p>
 * 라이브러리는 기본 구현으로 {@code DefaultPiiMaskingSanitizer}(이메일/휴대폰/주민번호/카드/Bearer 토큰 마스킹)를
 * 등록합니다. 사용자가 이 인터페이스를 구현한 빈을 등록하면 자동으로 교체됩니다.
 * 마스킹을 끄려면 {@code NoOpLoggingValueSanitizer}를 빈으로 등록하세요.
 * </p>
 * <p>
 * <b>원칙</b>: 로그에 민감정보를 안 넣는 것이 1차 방어, 본 마스킹은 2차 방어선입니다.
 * </p>
 */
@FunctionalInterface
public interface LoggingValueSanitizer {

    /**
     * 주어진 값에서 민감정보를 마스킹하여 반환합니다.
     *
     * @param key   MDC 키 (키별 차등 처리가 필요할 때 활용, 기본 구현은 무시)
     * @param value 원본 값 (null 가능)
     * @return 마스킹된 값 (null 입력 시 null)
     */
    String sanitize(String key, String value);
}
