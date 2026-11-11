package com.ids.keycloak.security.web.refresh;

/**
 * Keycloak을 서버끼리 부르는 세 가지: 갱신, 로그아웃, 토큰 폐기 (확장 지점, 01 설계 4-3). 기본은 {@link DefaultKeycloakTokenClient}.
 * 프록시·타임아웃·재시도를 바꾸려면 이 타입의 빈을 올린다. 모두 client 인증을 붙여 부른다.
 */
public interface KeycloakTokenClient {

    /**
     * 리프레시 토큰으로 새 토큰을 받는다.
     *
     * @throws KeycloakTokenException Keycloak이 거절했거나 부르지 못했다
     */
    KeycloakTokenResponse refresh(String refreshToken);

    /**
     * 리프레시 토큰으로 Keycloak 세션을 끝낸다 (OIDC 로그아웃 주소에 서버끼리 POST, #122). Keycloak SSO 세션이 끝난다.
     *
     * @throws KeycloakTokenException Keycloak이 거절했거나(이미 끝난 세션 등) 부르지 못했다
     */
    void logout(String refreshToken);

    /**
     * 리프레시 토큰을 폐기한다 (토큰 폐기 주소, RFC 7009). 로컬 로그아웃 때 옵션으로 쓴다.
     *
     * @throws KeycloakTokenException Keycloak이 거절했거나 부르지 못했다
     */
    void revoke(String refreshToken);
}
