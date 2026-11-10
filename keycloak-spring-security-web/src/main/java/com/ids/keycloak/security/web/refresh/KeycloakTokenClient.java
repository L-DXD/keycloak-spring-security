package com.ids.keycloak.security.web.refresh;

/**
 * Keycloak 토큰 주소 호출 (확장 지점, 01 설계 4-3). 기본은 {@link DefaultKeycloakTokenClient}.
 * 프록시·타임아웃·재시도를 바꾸려면 이 타입의 빈을 올린다.
 */
public interface KeycloakTokenClient {

    /**
     * 리프레시 토큰으로 새 토큰을 받는다.
     *
     * @throws KeycloakTokenException Keycloak이 거절했거나 부르지 못했다
     */
    KeycloakTokenResponse refresh(String refreshToken);
}
