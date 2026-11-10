package com.ids.keycloak.security.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 로그인한 사용자 (요청 인증, 01 설계 4-3). at 쿠키의 액세스 토큰에서 만든다. Keycloak도 DB도 부르지 않는다.
 * <ul>
 *   <li>{@link #getName()}은 Keycloak 사용자 id({@code sub})다</li>
 *   <li>{@link #sessionId()}는 Keycloak 세션 id({@code sid}), {@link #authorizedParty()}는 토큰을 받은 client({@code azp})다</li>
 *   <li>이름·이메일 같은 값은 토큰에 넣기로 한 앱만 {@link #claim}으로 읽는다. 기본 토큰에는 없다</li>
 * </ul>
 * 컨트롤러에서는 {@code @AuthenticationPrincipal KeycloakPrincipal user}로 받는다.
 * {@code toString()}에는 클레임을 넣지 않는다 (개인 정보가 로그에 남지 않게).
 */
public record KeycloakPrincipal(String subject, String sessionId, String authorizedParty, Map<String, Object> claims)
    implements AuthenticatedPrincipal, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    public KeycloakPrincipal {
        Objects.requireNonNull(subject, "subject");
        claims = claims == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    /** 검증을 통과한 액세스 토큰에서 만든다. */
    public static KeycloakPrincipal from(Jwt accessToken) {
        return new KeycloakPrincipal(accessToken.getSubject(), accessToken.getClaimAsString("sid"),
            accessToken.getClaimAsString("azp"), accessToken.getClaims());
    }

    /** Keycloak 사용자 id ({@code sub}). */
    @Override
    public String getName() {
        return subject;
    }

    /** 클레임 하나. 없으면 {@code null}. */
    public Object claim(String name) {
        return claims.get(name);
    }

    /** 클레임 하나를 문자열로. 없으면 {@code null}. */
    public String claimAsString(String name) {
        Object value = claims.get(name);
        return value == null ? null : value.toString();
    }

    /** {@code preferred_username}. 토큰에 없으면 {@code null}. */
    public String username() {
        return claimAsString("preferred_username");
    }

    @Override
    public String toString() {
        return "KeycloakPrincipal[subject=" + subject + ", sessionId=" + sessionId + ", authorizedParty=" + authorizedParty + "]";
    }
}
