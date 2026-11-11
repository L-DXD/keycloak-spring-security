package com.ids.keycloak.security.authentication;

import java.io.Serial;
import java.util.Collection;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 요청 인증 결과. principal은 {@link KeycloakPrincipal}, credentials는 검증한 액세스 토큰({@link Jwt})이다.
 * 만들 때 이미 인증된 상태다.
 */
public class KeycloakAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final KeycloakPrincipal principal;
    private final Jwt token;

    public KeycloakAuthenticationToken(KeycloakPrincipal principal, Jwt token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = Objects.requireNonNull(principal, "principal");
        this.token = Objects.requireNonNull(token, "token");
        setAuthenticated(true);
    }

    @Override
    public KeycloakPrincipal getPrincipal() {
        return principal;
    }

    /** 검증한 액세스 토큰. */
    @Override
    public Jwt getCredentials() {
        return token;
    }

    /** 검증한 액세스 토큰 ({@link #getCredentials()}와 같다). */
    public Jwt getToken() {
        return token;
    }
}
