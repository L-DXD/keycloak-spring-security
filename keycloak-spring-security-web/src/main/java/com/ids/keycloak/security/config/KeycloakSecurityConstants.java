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

    /** 백채널 로그아웃 URL 패턴 (Keycloak에서 호출) */
    public static final String BACK_CHANNEL_LOGOUT_URL = "/logout/connect/back-channel/**";

    /** ClientRegistration ID */
    public static final String REGISTRATION_ID = "keycloak";

    /** Spring Security 역할 접두사 */
    public static final String ROLE_PREFIX = "ROLE_";

    // ===== OIDC Claims =====

    /** 사용자 고유 식별자 클레임 */
    public static final String SUB_CLAIM = "sub";

    /** 사용자 명 클레임 */
    public static final String PREFERRED_USERNAME_CLAIM = "preferred_username";

    /** 세션 ID 클레임 */
    public static final String SID_CLAIM = "sid";
}
