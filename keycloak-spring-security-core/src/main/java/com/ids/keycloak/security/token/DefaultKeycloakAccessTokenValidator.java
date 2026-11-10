package com.ids.keycloak.security.token;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * 기본 액세스 토큰 검증 (JWT-01~08): JWKS 서명(RS256만) + iss + aud·azp + typ + 시간(오차 기본 30초).
 * <p>
 * 만료만 걸리면 {@code EXPIRED}(갱신 대상), 그 밖은 {@code INVALID}(갱신 안 함), JWKS를 못 받으면 {@code UNAVAILABLE}.
 * 규칙을 더하려면 {@link #validators()}를 바꾸는 하위 클래스를 만든다.
 */
public class DefaultKeycloakAccessTokenValidator implements KeycloakAccessTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(DefaultKeycloakAccessTokenValidator.class);

    private final String issuer;
    private final String clientId;
    private final String requiredAudience;
    private final Duration clockSkew;
    private final Clock clock;
    private final NimbusJwtDecoder decoder;

    /**
     * @param jwkSource        서명 키 ({@link KeycloakJwkSource})
     * @param issuer           realm 주소 (iss)
     * @param clientId         내 client id (azp)
     * @param requiredAudience aud에 있어야 하는 값
     * @param clockSkew        시간 오차
     * @param clock            시계
     */
    public DefaultKeycloakAccessTokenValidator(JWKSource<SecurityContext> jwkSource, String issuer, String clientId,
                                               String requiredAudience, Duration clockSkew, Clock clock) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.requiredAudience = requiredAudience;
        this.clockSkew = clockSkew;
        this.clock = clock;
        this.decoder = NimbusJwtDecoder.withJwkSource(jwkSource)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
        this.decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators()));
    }

    /** 검사 규칙. 하위 클래스가 더하거나 바꾼다. 생성자에서 한 번 부른다. */
    protected List<OAuth2TokenValidator<Jwt>> validators() {
        return List.of(new KeycloakTimestampValidator(clockSkew, clock), new KeycloakClaimsValidator(issuer, clientId, requiredAudience));
    }

    @Override
    public AccessTokenValidationResult validate(String token) {
        if (token == null || token.isBlank()) {
            return AccessTokenValidationResult.invalid("토큰이 없습니다");
        }
        try {
            return AccessTokenValidationResult.valid(decoder.decode(token));
        } catch (JwtValidationException e) {
            return classify(e.getErrors());
        } catch (BadJwtException e) {
            log.debug("[KSS] 액세스 토큰 거절: {}", e.getMessage());
            return AccessTokenValidationResult.invalid("서명·형식: " + e.getMessage());
        } catch (JwtException e) {
            log.warn("[KSS] 액세스 토큰을 검증하지 못했습니다 (JWKS): {}", e.getMessage());
            return AccessTokenValidationResult.unavailable(e.getMessage());
        }
    }

    private static AccessTokenValidationResult classify(Collection<OAuth2Error> errors) {
        String reason = errors.stream().map(OAuth2Error::getDescription).collect(Collectors.joining(", "));
        boolean onlyExpired = !errors.isEmpty() && errors.stream().allMatch(e -> KeycloakTokenErrors.EXPIRED.equals(e.getErrorCode()));
        if (onlyExpired) {
            return AccessTokenValidationResult.expired(reason);
        }
        log.debug("[KSS] 액세스 토큰 거절: {}", reason);
        return AccessTokenValidationResult.invalid(reason);
    }
}
