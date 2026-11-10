package com.ids.keycloak.security.token;

/**
 * 토큰 검증 오류 코드 (OAuth2Error code).
 */
public class KeycloakTokenErrors {

    /** 만료만 걸림. 갱신 대상. */
    public static final String EXPIRED = "kss_token_expired";

    /** 그 밖의 검증 실패. */
    public static final String INVALID = "kss_token_invalid";

    private KeycloakTokenErrors() {
    }
}
