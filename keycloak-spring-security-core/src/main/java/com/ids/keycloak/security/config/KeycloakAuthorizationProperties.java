package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Keycloak Security 인가(Authorization) 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     authorization:
 *       enabled: true
 *       cache:
 *         enabled: true
 *         ttl-seconds: 10
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakAuthorizationProperties {
    /**
     * Keycloak Authorization Services 사용 여부
     */
    private boolean enabled = false;

    /**
     * 인가 결정 캐시 설정.
     * {@code authorization.enabled=true}이고 {@code cache.enabled=true}일 때만 활성화됩니다.
     */
    @NestedConfigurationProperty
    private CacheProperties cache = new CacheProperties();

    /**
     * 인가 결정 캐시 관련 설정.
     */
    @Getter
    @Setter
    public static class CacheProperties {

        /**
         * 인가 결정 캐시 활성화 여부 (기본값: {@code false}).
         *
         * <p><b>기본 off(회귀 0):</b> 매 요청 Keycloak 인가 호출이 현행과 동일합니다.</p>
         * <p><b>true로 설정 시:</b> {@code ttl-seconds} 동안 동일 (사용자, 경로, 메서드) 조합의
         * 인가 결정을 캐시합니다. Keycloak Authorization Services 호출을 줄여 성능을 향상시키지만,
         * TTL 내 권한 변경은 즉시 반영되지 않습니다.</p>
         *
         * <pre>
         * keycloak:
         *   security:
         *     authorization:
         *       enabled: true
         *       cache:
         *         enabled: true
         *         ttl-seconds: 10
         * </pre>
         */
        private boolean enabled = false;

        /**
         * 캐시 TTL (초). 기본값 10초.
         * 너무 길면 권한 변경이 늦게 반영되고, 너무 짧으면 캐시 효과가 미미합니다.
         */
        private int ttlSeconds = 10;
    }
}
