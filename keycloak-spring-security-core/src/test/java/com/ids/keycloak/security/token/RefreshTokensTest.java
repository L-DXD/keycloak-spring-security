package com.ids.keycloak.security.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RefreshTokensTest {

    static String jwt(String payloadJson) {
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        return e.encodeToString("{\"alg\":\"HS512\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "."
            + e.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
    }

    @Test
    @DisplayName("Keycloak 리프레시 토큰(JWT)의 exp를 읽는다")
    void readsExp() {
        assertThat(RefreshTokens.expiresAt(jwt("{\"exp\":1794283200,\"typ\":\"Refresh\"}")))
            .contains(Instant.ofEpochSecond(1794283200));
    }

    @Test
    @DisplayName("JWT가 아니거나 exp가 없거나 0이면 빈 값 (오프라인 토큰 등)")
    void noExp() {
        assertThat(RefreshTokens.expiresAt("opaque-refresh-token")).isEmpty();
        assertThat(RefreshTokens.expiresAt(jwt("{\"typ\":\"Offline\"}"))).isEmpty();
        assertThat(RefreshTokens.expiresAt(jwt("{\"exp\":0}"))).isEmpty();
        assertThat(RefreshTokens.expiresAt(null)).isEmpty();
    }
}
