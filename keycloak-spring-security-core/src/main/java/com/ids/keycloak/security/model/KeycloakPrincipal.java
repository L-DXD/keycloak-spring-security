package com.ids.keycloak.security.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Keycloak으로 인증된 사용자를 나타내는 {@link OidcUser} 구현체입니다.
 * OIDC 로그인 시점과 API 요청 시점 모두에서 사용되는 통합 Principal 객체입니다.
 * <p>
 * 인증 완료 후 SecurityContext에 저장될 최종 Principal 객체입니다.
 * </p>
 *
 * <p><b>N-3 직렬화 지원:</b> {@code @JsonCreator}/@{@code @JsonProperty}를 사용하여
 * {@link com.fasterxml.jackson.databind.ObjectMapper}(GenericJackson2JsonRedisSerializer 포함)가
 * Redis 세션에서 역직렬화할 수 있도록 합니다.</p>
 */
@Getter
@JsonIgnoreProperties(value = {"attributes", "claims"}, ignoreUnknown = true)
public class KeycloakPrincipal implements OidcUser, OAuth2AuthenticatedPrincipal, Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final Collection<? extends GrantedAuthority> authorities;
    private final OidcIdToken idToken;
    private final OidcUserInfo userInfo;

    /**
     * OidcUser 정보를 기반으로 KeycloakPrincipal을 생성합니다.
     *
     * <p>{@code @JsonCreator}로 Jackson 역직렬화 진입점을 명시합니다(N-3).</p>
     *
     * @param name        사용자의 고유 식별자 (JWT 'sub' 클레임)
     * @param authorities 사용자의 권한 목록
     * @param idToken     OIDC ID Token
     * @param userInfo    OIDC UserInfo (null 가능)
     */
    @JsonCreator
    public KeycloakPrincipal(
        @JsonProperty("name") String name,
        @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities,
        @JsonProperty("idToken") OidcIdToken idToken,
        @JsonProperty("userInfo") OidcUserInfo userInfo
    ) {
        this.name = name;
        // N-3: List.of() 등 불변 컬렉션이 전달되면 Redis 역직렬화 시 AllowlistTypeIdResolver 문제 발생.
        // ArrayList로 복사하여 직렬화 형태를 ["java.util.ArrayList", [...]]로 고정.
        this.authorities = (authorities != null) ? new ArrayList<>(authorities) : new ArrayList<>();
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
