package com.ids.keycloak.security.authentication;

/**
 * Keycloak 인가에 사용할 Access Token을 제공하는 인터페이스.
 * <p>
 * {@link KeycloakAuthentication}, {@link BasicAuthenticationToken} 등
 * 라이브러리 자체 인증 토큰이 구현한다.
 * {@code KeycloakAuthorizationManager}는 이 인터페이스를 통해
 * 인증 타입에 무관하게 access token을 추출한다.
 */
public interface AccessTokenHolder {
    String getAccessToken();
}
