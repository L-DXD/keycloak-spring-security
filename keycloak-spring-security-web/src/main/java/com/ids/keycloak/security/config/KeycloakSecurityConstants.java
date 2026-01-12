package com.ids.keycloak.security.config;

/**
 * Keycloak Security 관련 상수를 정의하는 클래스입니다.
 */
public final class KeycloakSecurityConstants {

    private KeycloakSecurityConstants() {
        // 인스턴스화 방지
    }

    /** 프론트채널 로그아웃 URL */
    public static final String LOGOUT_URL = "/logout";

    /** ClientRegistration ID */
    public static final String REGISTRATION_ID = "keycloak";

    /** Spring Security 역할 접두사 */
    public static final String ROLE_PREFIX = "ROLE_";
}
