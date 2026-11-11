package com.ids.keycloak.security.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.token.AccessTokenValidationResult.Status;

/**
 * V3-04 액세스 토큰 로컬 검증 (JWT-01~08).
 */
class DefaultKeycloakAccessTokenValidatorTest {

    final TestTokens tokens = new TestTokens();
    final KeycloakJwkSource source = tokens.jwkSource();
    final DefaultKeycloakAccessTokenValidator validator = tokens.validator(source);

    @Test
    @DisplayName("JWT-01 서명·iss·aud·azp·typ·exp가 맞으면 통과하고 sub, sid를 꺼낸다")
    void validToken() {
        AccessTokenValidationResult result = validator.validate(tokens.token());

        assertThat(result.status()).isEqualTo(Status.VALID);
        assertThat(result.subject()).isEqualTo("user-1");
        assertThat(result.sessionId()).isEqualTo("kc-session-1");
        assertThat(result.jwt().getClaimAsString("azp")).isEqualTo("demo");
    }

    @Test
    @DisplayName("JWT-02 alg가 none이면 \"갱신 안 함\" 실패")
    void algNone() {
        assertThat(validator.validate(tokens.noneToken()).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-02 alg가 HS256이면 \"갱신 안 함\" 실패")
    void algHs256() {
        assertThat(validator.validate(tokens.hs256Token()).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-02 다른 키로 서명했으면 \"갱신 안 함\" 실패")
    void wrongSignature() {
        String forged = TestTokens.sign(TestTokens.newKey("k1"), tokens.claims().build());

        assertThat(validator.validate(forged).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-03 iss가 다르면 \"갱신 안 함\" 실패")
    void wrongIssuer() {
        AccessTokenValidationResult result = validator.validate(tokens.token(c -> c.issuer("https://sso.example.com/realms/other")));

        assertThat(result.status()).isEqualTo(Status.INVALID);
        assertThat(result.reason()).contains("iss");
    }

    @Test
    @DisplayName("JWT-04 aud에 내 client id가 없으면 \"갱신 안 함\" 실패")
    void missingAudience() {
        assertThat(validator.validate(tokens.token(c -> c.audience("account"))).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-04 azp가 다르면 \"갱신 안 함\" 실패")
    void wrongAzp() {
        AccessTokenValidationResult result = validator.validate(tokens.token(c -> c.claim("azp", "other-app")));

        assertThat(result.status()).isEqualTo(Status.INVALID);
        assertThat(result.reason()).contains("azp");
    }

    @Test
    @DisplayName("JWT-05 typ가 ID(ID 토큰을 at 자리에 넣음)면 \"갱신 안 함\" 실패")
    void idTokenInPlaceOfAccessToken() {
        assertThat(validator.validate(tokens.token(c -> c.claim("typ", "ID"))).status()).isEqualTo(Status.INVALID);
        assertThat(validator.validate(tokens.token(c -> c.claim("typ", "Refresh"))).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-06 exp가 31초 지났으면 \"만료(갱신 대상)\"")
    void expiredBeyondSkew() {
        String token = tokens.token();
        tokens.clock.advance(Duration.ofSeconds(60 + 31));

        AccessTokenValidationResult result = validator.validate(token);

        assertThat(result.status()).isEqualTo(Status.EXPIRED);
        assertThat(result.isRefreshable()).isTrue();
    }

    @Test
    @DisplayName("JWT-06 exp가 29초 지났으면 통과 (오차 30초)")
    void expiredWithinSkew() {
        String token = tokens.token();
        tokens.clock.advance(Duration.ofSeconds(60 + 29));

        assertThat(validator.validate(token).status()).isEqualTo(Status.VALID);
    }

    @Test
    @DisplayName("JWT-06 만료와 다른 실패가 같이 있으면 갱신하지 않는다")
    void expiredAndInvalid() {
        String token = tokens.token(c -> c.claim("azp", "other-app"));
        tokens.clock.advance(Duration.ofMinutes(5));

        assertThat(validator.validate(token).status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-07 nbf가 31초 넘게 미래면 \"갱신 안 함\" 실패")
    void notBeforeInFuture() {
        Instant now = tokens.clock.instant();

        String farFuture = tokens.token(c -> c.notBeforeTime(Date.from(now.plusSeconds(31))));
        String nearFuture = tokens.token(c -> c.notBeforeTime(Date.from(now.plusSeconds(29))));

        assertThat(validator.validate(farFuture).status()).isEqualTo(Status.INVALID);
        assertThat(validator.validate(nearFuture).status()).isEqualTo(Status.VALID);
    }

    @Test
    @DisplayName("JWT-07 iat가 31초 넘게 미래면 \"갱신 안 함\" 실패")
    void issuedAtInFuture() {
        Instant now = tokens.clock.instant();

        AccessTokenValidationResult result = validator.validate(tokens.token(c -> c
            .issueTime(Date.from(now.plusSeconds(31)))
            .expirationTime(Date.from(now.plusSeconds(120)))));

        assertThat(result.status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("JWT-08 모르는 kid가 1분 안에 두 번 오면 JWKS를 한 번만 다시 받는다. 두 번째는 로그아웃 대신 UNAVAILABLE")
    void unknownKidRefetchIsRateLimited() {
        assertThat(validator.validate(tokens.token()).isValid()).isTrue();
        assertThat(tokens.fetches.get()).as("처음 한 번 받는다").isEqualTo(1);
        tokens.clock.advance(Duration.ofMinutes(10));
        String unknown = TestTokens.sign(TestTokens.newKey("k-unknown"), tokens.claims().build());

        AccessTokenValidationResult first = validator.validate(unknown);
        tokens.clock.advance(Duration.ofSeconds(30));
        AccessTokenValidationResult second = validator.validate(unknown);

        assertThat(tokens.fetches.get()).as("모르는 kid로 다시 받는 것은 한 번").isEqualTo(2);
        assertThat(first.status()).as("다시 받아도 없는 키").isEqualTo(Status.INVALID);
        assertThat(second.status()).as("간격 제한으로 못 받음").isEqualTo(Status.UNAVAILABLE);
    }

    @Test
    @DisplayName("JWT-08 Keycloak이 키를 바꾸면 새 kid로 다시 받아 통과한다")
    void keyRotation() {
        assertThat(validator.validate(tokens.token()).isValid()).isTrue();
        tokens.clock.advance(Duration.ofMinutes(10));
        tokens.signingKey = TestTokens.newKey("k2");
        tokens.published = List.of(tokens.signingKey);

        AccessTokenValidationResult result = validator.validate(tokens.token());

        assertThat(result.isValid()).isTrue();
        assertThat(tokens.fetches.get()).isEqualTo(2);
    }

    @Test
    @DisplayName("JWKS를 받지 못하면 UNAVAILABLE (로그아웃하지 않는다)")
    void jwksUnavailable() {
        KeycloakJwkSource broken = new KeycloakJwkSource(() -> {
            throw new java.io.IOException("connection refused");
        }, tokens.clock);

        AccessTokenValidationResult result = tokens.validator(broken).validate(tokens.token());

        assertThat(result.status()).isEqualTo(Status.UNAVAILABLE);
    }

    @Test
    @DisplayName("토큰이 비었거나 JWT가 아니면 INVALID")
    void garbage() {
        assertThat(validator.validate(null).status()).isEqualTo(Status.INVALID);
        assertThat(validator.validate("").status()).isEqualTo(Status.INVALID);
        assertThat(validator.validate("not-a-jwt").status()).isEqualTo(Status.INVALID);
    }

    @Test
    @DisplayName("결과 사유에 토큰 값이 나오지 않는다")
    void reasonHasNoToken() {
        String token = tokens.token(c -> c.claim("azp", "other-app"));

        AccessTokenValidationResult result = validator.validate(token);

        assertThat(result.reason()).doesNotContain(token);
        assertThat(result.toString()).doesNotContain(token);
    }
}
