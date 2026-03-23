package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Basic Authentication 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     basic-auth:
 *       enabled: true  # 기본값: false (opt-in)
 * </pre>
 * </p>
 * <p>
 * Basic Auth가 활성화되면 {@code Authorization: Basic} 헤더를 통한 인증이
 * 기존 OIDC 쿠키 인증과 병렬로 동작합니다.
 * Keycloak의 Direct Access Grants (Resource Owner Password Credentials)를 통해
 * username/password를 토큰으로 교환하여 인증합니다.
 * </p>
 */
@Getter
@Setter
public class KeycloakBasicAuthProperties {

    /**
     * Basic Authentication 활성화 여부.
     * 기본값: false (opt-in 방식)
     */
    private boolean enabled = false;
}
