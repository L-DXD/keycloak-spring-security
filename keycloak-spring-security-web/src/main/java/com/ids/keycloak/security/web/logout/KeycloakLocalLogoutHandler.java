package com.ids.keycloak.security.web.logout;

import java.time.Clock;
import java.util.Objects;

import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로컬 로그아웃: sid 쿠키가 가리키는 세션 행을 지우고, 쿠키 4개를 지우고, ENDED 이벤트(사유)를 낸다.
 * Keycloak 로그아웃은 부르지 않는다. 토큰 검증 실패(REQ-04)에 쓴다. 옵션을 켜면 사유가 {@code invalid_token}일 때
 * 리프레시 토큰을 폐기한다({@link KeycloakRefreshTokenRevoker}, LOGOUT-06).
 */
public class KeycloakLocalLogoutHandler {

    private final KeycloakSessionStore store;
    private final KeycloakCookieWriter cookies;
    private final KeycloakSessionEventPublisher events;
    private final Clock clock;
    private final KeycloakRefreshTokenRevoker revoker;

    public KeycloakLocalLogoutHandler(KeycloakSessionStore store, KeycloakCookieWriter cookies, KeycloakSessionEventPublisher events,
                                      Clock clock, KeycloakRefreshTokenRevoker revoker) {
        this.store = Objects.requireNonNull(store);
        this.cookies = Objects.requireNonNull(cookies);
        this.events = Objects.requireNonNull(events);
        this.clock = Objects.requireNonNull(clock);
        this.revoker = Objects.requireNonNull(revoker);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response, KeycloakSessionEndReason reason) {
        Objects.requireNonNull(reason, "reason");
        cookies.read(request, KeycloakCookie.SESSION)
            .filter(SessionIds::looksLikeSid)
            .flatMap(sid -> store.deleteBySidHash(SessionIds.hash(sid)))
            .ifPresent(record -> {
                events.publish(KeycloakSessionEvent.ended(record, reason, clock.instant()));
                if (reason == KeycloakSessionEndReason.INVALID_TOKEN) {
                    revoker.revoke(record);
                }
            });
        cookies.clearAll(response);
    }
}
