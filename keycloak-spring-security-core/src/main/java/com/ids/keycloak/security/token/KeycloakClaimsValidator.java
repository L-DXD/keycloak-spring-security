package com.ids.keycloak.security.token;

import java.util.List;
import java.util.Objects;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Keycloak 액세스 토큰 클레임 검사 (JWT-03·04·05).
 * <ul>
 *   <li>{@code iss}가 realm 주소와 같다</li>
 *   <li>{@code aud}에 필요한 값(기본 client id)이 있다</li>
 *   <li>{@code azp}가 내 client id다 (다른 client가 받은 토큰을 거절)</li>
 *   <li>{@code typ}가 {@code Bearer}다 (ID 토큰·리프레시 토큰을 at 자리에 넣은 것을 거절)</li>
 *   <li>{@code sub}가 있다</li>
 * </ul>
 */
public class KeycloakClaimsValidator implements OAuth2TokenValidator<Jwt> {

    /** Keycloak 액세스 토큰의 typ 클레임 값. */
    public static final String ACCESS_TOKEN_TYPE = "Bearer";

    private final String issuer;
    private final String clientId;
    private final String requiredAudience;

    public KeycloakClaimsValidator(String issuer, String clientId, String requiredAudience) {
        this.issuer = Objects.requireNonNull(issuer);
        this.clientId = Objects.requireNonNull(clientId);
        this.requiredAudience = Objects.requireNonNull(requiredAudience);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String iss = jwt.getClaimAsString("iss");
        if (!issuer.equals(iss)) {
            return invalid("iss가 다릅니다");
        }
        List<String> audience = jwt.getAudience();
        if (audience == null || !audience.contains(requiredAudience)) {
            return invalid("aud에 " + requiredAudience + "가 없습니다");
        }
        if (!clientId.equals(jwt.getClaimAsString("azp"))) {
            return invalid("azp가 " + clientId + "가 아닙니다");
        }
        if (!ACCESS_TOKEN_TYPE.equals(jwt.getClaimAsString("typ"))) {
            return invalid("typ가 Bearer가 아닙니다");
        }
        if (jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            return invalid("sub가 없습니다");
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult invalid(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(KeycloakTokenErrors.INVALID, description, null));
    }
}
