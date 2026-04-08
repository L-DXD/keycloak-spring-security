package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.util.Collections;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Basic Authentication 인증 과정을 나타내는 {@link org.springframework.security.core.Authentication} 구현체입니다.
 * <p>
 * 인증 전: {@code username}과 {@code password}를 담는 미인증 토큰으로 생성됩니다.
 * 인증 후: {@link BasicAuthenticationProvider}가 Keycloak Direct Access Grants로 토큰을 교환한 후,
 * {@link KeycloakPrincipal}을 설정한 인증 완료 토큰을 반환합니다.
 * </p>
 * <p>
 * {@link KeycloakAuthentication}을 상속하지 않는 이유:
 * OIDC 쿠키 흐름과 Basic 흐름의 인증 전 데이터가 다릅니다 (쿠키 토큰 vs username/password).
 * </p>
 */
public class BasicAuthenticationToken extends AbstractAuthenticationToken implements AccessTokenHolder {

    private final String username;
    private String password;
    private KeycloakPrincipal principal;
    private String idToken;
    private String accessToken;

    /**
     * 인증 전 토큰을 생성합니다.
     *
     * @param username 사용자 이름
     * @param password 사용자 비밀번호
     */
    public BasicAuthenticationToken(String username, String password) {
        super(Collections.emptyList());
        this.username = username;
        this.password = password;
        setAuthenticated(false);
    }

    /**
     * 인증 완료 토큰을 생성합니다.
     *
     * @param principal   Keycloak에서 반환된 Principal
     * @param idToken     ID Token
     * @param accessToken Access Token
     */
    public BasicAuthenticationToken(KeycloakPrincipal principal, String idToken, String accessToken) {
        super(principal.getAuthorities());
        this.username = principal.getName();
        this.password = null;
        this.principal = principal;
        this.idToken = idToken;
        this.accessToken = accessToken;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.password;
    }

    @Override
    public Object getPrincipal() {
        return this.principal != null ? this.principal : this.username;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public String getIdToken() {
        return this.idToken;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.password = null;
    }
}
