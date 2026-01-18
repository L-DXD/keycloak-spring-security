package com.ids.keycloak.security.config;

import java.time.Duration;
import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak 세션 저장소 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml 예시:
 * <pre>
 * keycloak:
 *   security:
 *      session:
 *          store-type: memory  # 또는 redis
 *          timeout: 30m        # 세션 만료 시간 (기본값: 30분)
 * </pre>
 * </p>
 */
@Getter
public class KeycloakSessionProperties {

    /**
     * 세션 저장소 유형 (MEMORY 또는 REDIS)
     * 기본값: MEMORY (하위 호환성 유지)
     */
    private SessionStoreType storeType = SessionStoreType.MEMORY;

    /**
     * 세션 만료 시간.
     * 기본값: 30분
     */
    private Duration timeout = Duration.ofMinutes(30);
}
