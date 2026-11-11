package com.ids.keycloak.security.web.refresh;

import java.time.Duration;
import java.util.Objects;

import org.springframework.security.oauth2.jwt.Jwt;

import com.ids.keycloak.security.event.KeycloakSessionEndReason;

/**
 * 갱신 결과.
 * <ul>
 *   <li>{@link Status#REFRESHED}: Keycloak에서 새 토큰을 받았다</li>
 *   <li>{@link Status#REUSED}: 같은 세션을 다른 요청이 방금 갱신했다. Keycloak을 다시 부르지 않고 그 토큰을 쓴다</li>
 *   <li>{@link Status#SESSION_ENDED}: 세션이 끝났다(행 없음, 절대 상한, 리프레시 만료, Keycloak 거절 …). 행은 이미 지웠다</li>
 *   <li>{@link Status#UNAVAILABLE}: Keycloak을 부르지 못했다. 세션은 그대로다</li>
 * </ul>
 *
 * @param accessToken          REFRESHED·REUSED일 때 새 액세스 토큰 (검증 통과)
 * @param accessTokenCookieAge REFRESHED·REUSED일 때 at 쿠키 수명 (토큰 남은 시간과 절대 상한 남은 시간 중 짧은 것)
 * @param endReason            SESSION_ENDED일 때 사유. 행이 처음부터 없었으면 {@code null}
 */
public record KeycloakRefreshResult(Status status, Jwt accessToken, Duration accessTokenCookieAge, KeycloakSessionEndReason endReason) {

    /** 결과 종류. */
    public enum Status {
        REFRESHED, REUSED, SESSION_ENDED, UNAVAILABLE
    }

    public KeycloakRefreshResult {
        Objects.requireNonNull(status, "status");
    }

    public static KeycloakRefreshResult refreshed(Jwt accessToken, Duration cookieAge) {
        return new KeycloakRefreshResult(Status.REFRESHED, Objects.requireNonNull(accessToken), cookieAge, null);
    }

    public static KeycloakRefreshResult reused(Jwt accessToken, Duration cookieAge) {
        return new KeycloakRefreshResult(Status.REUSED, Objects.requireNonNull(accessToken), cookieAge, null);
    }

    public static KeycloakRefreshResult sessionEnded(KeycloakSessionEndReason reason) {
        return new KeycloakRefreshResult(Status.SESSION_ENDED, null, null, reason);
    }

    public static KeycloakRefreshResult unavailable() {
        return new KeycloakRefreshResult(Status.UNAVAILABLE, null, null, null);
    }

    /** 요청을 로그인한 채로 이어 가도 되는가 (REFRESHED·REUSED). */
    public boolean hasAccessToken() {
        return accessToken != null;
    }
}
