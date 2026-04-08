package com.ids.keycloak.security.authentication;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * HTTP Basic Auth(사용자명/비밀번호) 인증에서 발급된 Keycloak Access Token을
 * 보관하는 {@link org.springframework.security.core.Authentication} 구현체.
 * <p>
 * {@link AccessTokenHolder}를 구현하므로 {@code KeycloakAuthorizationManager}가
 * 인증 타입에 무관하게 access token을 추출할 수 있다.
 */
public class BasicAuthenticationToken extends AbstractAuthenticationToken implements AccessTokenHolder {

    private final String principal;
    private final String accessToken;

    /**
     * BasicAuthenticationToken 을 생성합니다.
     *
     * @param principal     사용자명(username) 또는 식별자.
     * @param accessToken   Keycloak Basic Auth 인증으로 발급된 Access Token.
     * @param authorities   부여된 권한 목록.
     * @param authenticated 인증 완료 여부.
     */
    public BasicAuthenticationToken(
        String principal,
        String accessToken,
        Collection<? extends GrantedAuthority> authorities,
        boolean authenticated
    ) {
        super(authorities);
        this.principal = principal;
        this.accessToken = accessToken;
        setAuthenticated(authenticated);
    }

    /**
     * 자격 증명(Credentials)으로 Access Token을 반환합니다.
     *
     * @return Access Token 문자열
     */
    @Override
    public Object getCredentials() {
        return this.accessToken;
    }

    /**
     * Principal(주체)을 반환합니다.
     *
     * @return 사용자명 문자열
     */
    @Override
    public String getPrincipal() {
        return this.principal;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Keycloak 인가에 사용될 Access Token을 반환합니다.
     */
    @Override
    public String getAccessToken() {
        return this.accessToken;
    }
}
