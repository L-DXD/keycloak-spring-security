package com.ids.keycloak.security.token;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import com.nimbusds.jwt.JWTParser;

/**
 * Keycloak 리프레시 토큰의 만료 시각. Keycloak 리프레시 토큰은 JWT라서 exp를 읽는다.
 * <p>
 * 서명은 확인하지 않는다: 이 값은 앱이 Keycloak 토큰 주소에서 TLS로 직접 받은 것이고, 만료 시각을 행에 적는 데만 쓴다.
 * JWT가 아니거나 exp가 없으면(오프라인 토큰 등) 빈 값.
 */
public class RefreshTokens {

    private RefreshTokens() {
    }

    public static Optional<Instant> expiresAt(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        try {
            Date exp = JWTParser.parse(refreshToken).getJWTClaimsSet().getExpirationTime();
            return exp == null || exp.getTime() <= 0 ? Optional.empty() : Optional.of(exp.toInstant());
        } catch (ParseException | RuntimeException e) {
            return Optional.empty();
        }
    }
}
