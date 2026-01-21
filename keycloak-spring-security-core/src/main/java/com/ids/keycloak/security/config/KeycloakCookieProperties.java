package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak Security 쿠키 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     cookie:
 *       http-only: true
 *       secure: true
 *       same-site: Lax
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakCookieProperties {
    private boolean httpOnly = true;
    private boolean secure = false;
    private String domain;
    private String path = "/";
    private String sameSite; // Lax, Strict, None
}
