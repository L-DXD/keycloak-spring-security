package com.ids.keycloak.security.ratelimit;

/**
 * Rate Limiting 판단을 수행하는 인터페이스입니다.
 * <p>
 * 기본 구현체로 {@link InMemoryRateLimiter}가 제공되며,
 * 분산 환경에서는 Redis 기반 등 커스텀 구현체를 빈으로 등록하여 교체할 수 있습니다.
 * </p>
 */
public interface RateLimiter {

    /**
     * 요청 허용 여부를 판단하고 카운트를 증가시킵니다.
     *
     * @param key rate limit 키 (IP, username, 또는 복합)
     * @return 허용되면 true, 차단이면 false
     */
    boolean tryAcquire(String key);

    /**
     * 차단 해제까지 남은 시간(초)을 반환합니다.
     *
     * @param key rate limit 키
     * @return 남은 차단 시간(초), 차단 중이 아니면 0
     */
    long getRetryAfterSeconds(String key);
}
