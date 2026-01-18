package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak Security 인가(Authorization) 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     authorization:
 *       enabled: true
 * </pre>
 * </p>
 */
@Getter
public class KeycloakAuthorizationProperties {
    /**
     * Keycloak Authorization Services 사용 여부
     */
    private boolean enabled = false;
}
