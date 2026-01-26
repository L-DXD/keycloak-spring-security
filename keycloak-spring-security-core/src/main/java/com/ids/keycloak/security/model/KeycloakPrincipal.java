package com.ids.keycloak.security.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Keycloak으로 인증된 사용자를 나타내는 {@link OidcUser} 구현체입니다.
 * OIDC 로그인 시점과 API 요청 시점 모두에서 사용되는 통합 Principal 객체입니다.
 * <p>
 * 인증 완료 후 SecurityContext에 저장될 최종 Principal 객체입니다.
 * </p>
 */
@Getter
public class KeycloakPrincipal implements OidcUser, Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final Collection<? extends GrantedAuthority> authorities;
    private final OidcIdToken idToken;
    private final OidcUserInfo userInfo;

    /**
     * OidcUser 정보를 기반으로 KeycloakPrincipal을 생성합니다.
     *
     * @param name        사용자의 고유 식별자 (JWT 'sub' 클레임)
     * @param authorities 사용자의 권한 목록
     * @param idToken     OIDC ID Token
     * @param userInfo    OIDC UserInfo (null 가능)
     */
    public KeycloakPrincipal(
        String name,
        Collection<? extends GrantedAuthority> authorities,
        OidcIdToken idToken,
        OidcUserInfo userInfo
    ) {
        this.name = name;
        this.authorities = authorities;
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    /**
     * ID Token과 UserInfo의 클레임을 합쳐서 반환합니다.
     * UserInfo가 null인 경우 ID Token 클레임만 반환합니다.
     *
     * @return 합쳐진 클레임 맵
     */
    @Override
    public Map<String, Object> getClaims() {
        Map<String, Object> claims = new HashMap<>();
        if (this.idToken != null) {
            claims.putAll(this.idToken.getClaims());
        }
        if (this.userInfo != null) {
            claims.putAll(this.userInfo.getClaims());
        }
        return claims;
    }

    /**
     * OAuth2User 호환을 위해 클레임을 attributes로 반환합니다.
     *
     * @return 클레임 맵
     */
    @Override
    public Map<String, Object> getAttributes() {
        return getClaims();
    }
}
