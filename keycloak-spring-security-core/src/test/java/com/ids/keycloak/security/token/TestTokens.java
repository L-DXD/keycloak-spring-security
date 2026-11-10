package com.ids.keycloak.security.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 * 테스트용 Keycloak 흉내: RSA 키로 액세스 토큰을 만들고, JWKS를 돌려준다.
 */
class TestTokens {

    static final String ISSUER = "https://sso.example.com/realms/demo";
    static final String CLIENT_ID = "demo";

    final MutableClock clock = new MutableClock(Instant.parse("2026-11-10T00:00:00Z"));
    final AtomicInteger fetches = new AtomicInteger();
    RSAKey signingKey = newKey("k1");
    List<RSAKey> published = List.of(signingKey);

    static RSAKey newKey(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    JwkSetFetcher fetcher() {
        return () -> {
            fetches.incrementAndGet();
            return new JWKSet(published.stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList()).toString();
        };
    }

    KeycloakJwkSource jwkSource() {
        return new KeycloakJwkSource(fetcher(), clock);
    }

    DefaultKeycloakAccessTokenValidator validator(KeycloakJwkSource source) {
        return new DefaultKeycloakAccessTokenValidator(source, ISSUER, CLIENT_ID, CLIENT_ID, Duration.ofSeconds(30), clock);
    }

    /** Keycloak 액세스 토큰 모양의 클레임 (지금 발급, 60초 유효). */
    JWTClaimsSet.Builder claims() {
        Instant now = clock.instant();
        return new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject("user-1")
            .audience(List.of(CLIENT_ID, "account"))
            .claim("azp", CLIENT_ID)
            .claim("typ", "Bearer")
            .claim("sid", "kc-session-1")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(60)));
    }

    String token(Consumer<JWTClaimsSet.Builder> change) {
        JWTClaimsSet.Builder builder = claims();
        change.accept(builder);
        return sign(signingKey, builder.build());
    }

    String token() {
        return token(c -> { });
    }

    static String sign(RSAKey key, JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String hs256Token() {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(signingKey.getKeyID()).build(), claims().build());
            jwt.sign(new MACSigner(new byte[32]));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String noneToken() {
        return new PlainJWT(claims().build()).serialize();
    }

    /** 테스트가 앞으로 돌리는 시계. */
    static class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
