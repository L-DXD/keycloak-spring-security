package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Keycloak 세션 저장소 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml 예시:
 * <pre>
 * keycloak:
 *   session:
 *     store-type: memory  # 또는 redis
 * </pre>
 * </p>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak.session")
public class KeycloakSessionProperties {

    /**
     * 세션 저장소 유형 (MEMORY 또는 REDIS)
     * 기본값: MEMORY (하위 호환성 유지)
     */
    private SessionStoreType storeType = SessionStoreType.MEMORY;
}
