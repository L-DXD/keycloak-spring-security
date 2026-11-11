package com.ids.keycloak.security.web.logout;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;

import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * back-channel 로그아웃 (V3-12, 01 설계 4-9): Keycloak이 서버끼리 보낸 {@code logout_token}의 {@code sid}로 세션 행을 지운다.
 * <p>
 * 토큰 검증(서명·iss·aud·iat·jti·events, nonce 없음)은 Spring Security의 back-channel 로그아웃 필터가 먼저 한다. 이 처리기는
 * 검증을 통과한 토큰만 받는다. 브라우저 요청이 아니라 쿠키는 건드리지 않는다. 지운 행마다 ENDED 이벤트(사유 {@code backchannel_logout})를 낸다.
 * 행이 이미 없어도 200이다. {@code sid}가 없는 토큰(사용자 전체 로그아웃)은 400으로 돌린다: Keycloak 클라이언트의
 * "Backchannel logout session required"를 켜야 한다.
 */
public class KeycloakBackChannelLogoutHandler implements LogoutHandler {

    private static final Logger log = LoggerFactory.getLogger(KeycloakBackChannelLogoutHandler.class);
    private static final String SPEC = "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation";

    private final KeycloakSessionStore store;
    private final KeycloakSessionEventPublisher events;
    private final Clock clock;
    private final OAuth2ErrorHttpMessageConverter errors = new OAuth2ErrorHttpMessageConverter();

    public KeycloakBackChannelLogoutHandler(KeycloakSessionStore store, KeycloakSessionEventPublisher events, Clock clock) {
        this.store = Objects.requireNonNull(store);
        this.events = Objects.requireNonNull(events);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        OidcLogoutToken token = authentication != null && authentication.getPrincipal() instanceof OidcLogoutToken t ? t : null;
        if (token == null || !StringUtils.hasText(token.getSessionId())) {
            log.warn("[KSS] sid가 없는 logout_token은 처리하지 않습니다. Keycloak 클라이언트의 'Backchannel logout session required'를 켜세요");
            badRequest(response, "sid claim is required");
            return;
        }
        List<KeycloakSessionRecord> ended = store.deleteByKcSid(token.getSessionId());
        Instant now = clock.instant();
        for (KeycloakSessionRecord row : ended) {
            events.publish(KeycloakSessionEvent.ended(row, KeycloakSessionEndReason.BACKCHANNEL_LOGOUT, now));
        }
        log.debug("[KSS] back-channel 로그아웃: 세션 행 {}개를 지웠습니다", ended.size());
    }

    private void badRequest(HttpServletResponse response, String description) {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        try {
            errors.write(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, description, SPEC), MediaType.APPLICATION_JSON,
                new ServletServerHttpResponse(response));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
