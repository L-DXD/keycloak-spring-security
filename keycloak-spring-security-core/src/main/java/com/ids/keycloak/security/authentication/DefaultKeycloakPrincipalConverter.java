package com.ids.keycloak.security.authentication;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 기본 변환: {@link KeycloakPrincipal}(sub, sid, azp, 클레임) + 권한 없음.
 * 토큰에 역할을 싣지 않는 것이 기본이다(01 설계 3-2). 권한이 필요하면 {@link #authorities}를 덮어쓴다.
 */
public class DefaultKeycloakPrincipalConverter implements KeycloakPrincipalConverter {

    @Override
    public Authentication convert(Jwt accessToken) {
        return new KeycloakAuthenticationToken(principal(accessToken), accessToken, authorities(accessToken));
    }

    protected KeycloakPrincipal principal(Jwt accessToken) {
        return KeycloakPrincipal.from(accessToken);
    }

    /** 권한. 기본은 없음. */
    protected Collection<? extends GrantedAuthority> authorities(Jwt accessToken) {
        return List.of();
    }
}
