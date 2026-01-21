package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Keycloak 인증 과정을 나타내는 {@link org.springframework.security.core.Authentication} 구현체입니다.
 * 인증 전/후 모두 {@link KeycloakPrincipal}을 Principal로 사용합니다.
 * 인증 검증은 idToken을 기준으로 합니다.
 */
public class KeycloakAuthentication extends AbstractAuthenticationToken {

    private final KeycloakPrincipal principal;
    private final String idToken;
    private final String accessToken;

    /**
     * Authentication 객체를 생성합니다.
     *
     * @param principal     사용자 Principal (KeycloakPrincipal).
     * @param idToken       검증에 사용될 ID Token.
     * @param accessToken   Access Token (OAuth2AuthorizedClient 생성을 위해 보관).
     * @param authenticated 인증 완료 여부.
     */
    public KeycloakAuthentication(KeycloakPrincipal principal, String idToken, String accessToken, boolean authenticated) {
        super(principal.getAuthorities());
        this.principal = principal;
        this.idToken = idToken;
        this.accessToken = accessToken;
        setAuthenticated(authenticated);
    }

    /**
     * 자격 증명(Credentials)으로 ID Token을 반환합니다.
     *
     * @return ID Token 문자열
     */
    @Override
    public Object getCredentials() {
        return this.idToken;
    }

    /**
     * Principal(주체)을 반환합니다.
     *
     * @return {@code KeycloakPrincipal}
     */
    @Override
    public KeycloakPrincipal getPrincipal() {
        return this.principal;
    }

    /**
     * ID Token을 반환합니다.
     *
     * @return ID Token 문자열
     */
    public String getIdToken() {
        return this.idToken;
    }

    /**
     * Access Token을 반환합니다.
     *
     * @return Access Token 문자열
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * 인증 후에도 Credentials(idToken) 정보를 유지하기 위해,
     * 부모 클래스의 eraseCredentials()가 자격 증명을 null로 만들지 않도록 아무 작업도 하지 않도록 재정의합니다.
     */
    @Override
    public void eraseCredentials() {
        // 부모 클래스의 기본 동작(credentials를 null로 설정)을 방지합니다.
    }
}
