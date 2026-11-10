package com.ids.keycloak.security.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 시간 검사 (JWT-06·07). 만료는 {@link KeycloakTokenErrors#EXPIRED}로, 미래 시각(nbf·iat)은 {@link KeycloakTokenErrors#INVALID}로 나눈다.
 * <p>
 * Spring의 {@code JwtTimestampValidator}는 둘을 같은 코드로 돌려줘서 "갱신할지"를 가를 수 없어 따로 둔다.
 */
public class KeycloakTimestampValidator implements OAuth2TokenValidator<Jwt> {

    private final Duration clockSkew;
    private final Clock clock;

    public KeycloakTimestampValidator(Duration clockSkew, Clock clock) {
        this.clockSkew = Objects.requireNonNull(clockSkew);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Instant now = clock.instant();
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt == null) {
            return failure(KeycloakTokenErrors.INVALID, "exp가 없습니다");
        }
        Instant notBefore = jwt.getNotBefore();
        if (notBefore != null && notBefore.isAfter(now.plus(clockSkew))) {
            return failure(KeycloakTokenErrors.INVALID, "nbf가 미래입니다");
        }
        Instant issuedAt = jwt.getIssuedAt();
        if (issuedAt != null && issuedAt.isAfter(now.plus(clockSkew))) {
            return failure(KeycloakTokenErrors.INVALID, "iat가 미래입니다");
        }
        if (now.minus(clockSkew).isAfter(expiresAt)) {
            return failure(KeycloakTokenErrors.EXPIRED, "만료됐습니다");
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult failure(String code, String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(code, description, null));
    }
}
