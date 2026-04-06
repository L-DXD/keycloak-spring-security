package com.ids.keycloak.security.ratelimit;

/**
 * Rate Limiting 판단을 수행하는 인터페이스입니다.
 * <p>
 * 기본 구현체로 {@link InMemoryRateLimiter}가 제공되며,
 * 분산 환경에서는 Redis 기반 등 커스텀 구현체를 빈으로 등록하여 교체할 수 있습니다.
 * </p>
 * <p>
 * 브루트포스 방지 목적이므로 인증 실패 시에만 카운트합니다.
 * 요청 전에 {@link #isBlocked(String)}로 차단 여부를 확인하고,
 * 인증 실패 시 {@link #recordFailure(String)}로 실패를 기록합니다.
 * </p>
 */
public interface RateLimiter {

    /**
     * 해당 키가 현재 차단 상태인지 확인합니다.
     * 카운트를 증가시키지 않고 차단 여부만 판단합니다.
     *
     * @param key rate limit 키 (IP, username, 또는 복합)
     * @return 차단 중이면 true, 허용이면 false
     */
    boolean isBlocked(String key);

    /**
     * 인증 실패를 기록합니다. 실패 카운트를 증가시키고,
     * 임계치 초과 시 차단 상태로 전환합니다.
     *
     * @param key rate limit 키 (IP, username, 또는 복합)
     */
    void recordFailure(String key);

    /**
     * 차단 해제까지 남은 시간(초)을 반환합니다.
     *
     * @param key rate limit 키
     * @return 남은 차단 시간(초), 차단 중이 아니면 0
     */
    long getRetryAfterSeconds(String key);
}
