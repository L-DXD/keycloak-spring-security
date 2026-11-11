package com.ids.keycloak.security.web.refresh;

import java.time.Instant;
import java.util.Objects;

/**
 * Keycloak 갱신 응답에서 라이브러리가 쓰는 값. ID 토큰은 받지 않는다(저장하지 않으므로).
 *
 * @param accessToken      새 액세스 토큰 (JWT)
 * @param refreshToken     새 리프레시 토큰. Keycloak이 주지 않았으면 {@code null}(예전 것을 계속 쓴다)
 * @param refreshExpiresAt 새 리프레시 토큰 만료 ({@code refresh_expires_in}). 모르면 {@code null}
 */
public record KeycloakTokenResponse(String accessToken, String refreshToken, Instant refreshExpiresAt) {

    public KeycloakTokenResponse {
        Objects.requireNonNull(accessToken, "accessToken");
    }

    @Override
    public String toString() {
        return "KeycloakTokenResponse[refreshExpiresAt=" + refreshExpiresAt + "]";
    }
}
