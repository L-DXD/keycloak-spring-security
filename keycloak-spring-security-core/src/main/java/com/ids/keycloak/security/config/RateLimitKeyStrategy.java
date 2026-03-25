package com.ids.keycloak.security.config;

/**
 * Rate Limiting 키 전략을 정의하는 열거형입니다.
 * <p>
 * Rate Limit 판단 시 어떤 기준으로 요청을 그룹핑할지 결정합니다.
 * </p>
 */
public enum RateLimitKeyStrategy {

    /**
     * IP 주소 기반으로만 제한합니다.
     * 동일 IP에서의 대량 요청을 차단합니다.
     */
    IP,

    /**
     * username 기반으로만 제한합니다.
     * 분산 IP에서 동일 계정 공격(credential stuffing)을 차단합니다.
     */
    USERNAME,

    /**
     * IP와 username 모두 적용합니다.
     * 두 기준 중 하나라도 초과 시 차단합니다.
     */
    IP_AND_USERNAME
}
