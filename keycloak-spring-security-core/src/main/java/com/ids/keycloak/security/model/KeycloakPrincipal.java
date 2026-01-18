package com.ids.keycloak.security.model;

import java.security.Principal;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

/**
 * Keycloak으로 인증된 사용자를 나타내는 {@link OAuth2User} 구현체입니다.
 * 인증 완료 후 SecurityContext에 저장될 최종 Principal 객체입니다.
 *
 * @param name        사용자의 고유 식별자 (JWT 'sub' 클레임). {@link OAuth2User#getName()}의 반환값이 됩니다.
 * @param authorities 사용자의 권한 목록.
 * @param attributes  JWT 토큰의 전체 클레임을 담는 맵.
 */
public record KeycloakPrincipal(
    String name,
    Collection<? extends GrantedAuthority> authorities,
    Map<String, Object> attributes
) implements OAuth2User, Serializable {
    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return this.name;
    }
}
