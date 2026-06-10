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
 *       secure: true   # 기본값 true (secure-by-default)
 *       same-site: Lax
 * </pre>
 * </p>
 *
 * <p><b>Breaking Change (v1.9.0+):</b> {@code secure} 기본값이 {@code false}에서 {@code true}로 변경되었습니다.
 * HTTP(비TLS) 로컬 개발 환경에서는 쿠키가 전송되지 않을 수 있으므로,
 * 아래와 같이 명시적으로 비활성화하세요:
 * <pre>
 * keycloak:
 *   security:
 *     cookie:
 *       secure: false   # 로컬 HTTP 환경에서만 사용
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakCookieProperties {
    private boolean httpOnly = true;
    /**
     * Secure 쿠키 플래그 (기본값: {@code true}).
     *
     * <p>HTTPS 환경에서만 쿠키가 전송되도록 보장합니다(secure-by-default).
     * HTTP(비TLS) 로컬 개발 환경에서는 {@code keycloak.security.cookie.secure=false}로 명시 해제하세요.</p>
     */
    private boolean secure = true;
    private String domain;
    private String path = "/";
    private String sameSite; // Lax, Strict, None
}
