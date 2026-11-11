package com.ids.keycloak.security.web.logout;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * {@code POST /logout} (V3-11, 01 설계 4-8): sid 쿠키의 세션 행을 지우고(ENDED, 사유 {@code logout}) 쿠키 4개를 지운 뒤,
 * 행의 리프레시 토큰으로 Keycloak 로그아웃을 서버끼리 부른다. 결과는 요청 속성 {@link #RESULT_ATTRIBUTE}에 남기고
 * {@link KeycloakLogoutSuccessHandler}가 보고 어디로 보낼지 정한다.
 * <p>
 * 행을 먼저 지운다: Keycloak이 로그아웃하며 보내는 back-channel 로그아웃이 같은 행을 또 끝내지 않게(이벤트가 두 번 나지 않게).
 */
public class KeycloakLogoutHandler implements LogoutHandler {

    /** Keycloak 로그아웃 결과. */
    public enum Result {
        /** 세션 행이 없었다 (이미 로그아웃, 쿠키 없음). Keycloak을 부르지 않았다 */
        NO_SESSION,
        /** Keycloak 로그아웃이 됐다 */
        KEYCLOAK_LOGGED_OUT,
        /** Keycloak 로그아웃을 하지 못했다 (Keycloak 거절·연결 실패·토큰을 풀지 못함). 브라우저를 OIDC 로그아웃 주소로 보낸다 */
        KEYCLOAK_FAILED
    }

    /** 결과를 담는 요청 속성 이름. */
    public static final String RESULT_ATTRIBUTE = KeycloakLogoutHandler.class.getName() + ".RESULT";

    private static final Logger log = LoggerFactory.getLogger(KeycloakLogoutHandler.class);

    private final KeycloakSessionStore store;
    private final TokenCipher cipher;
    private final KeycloakTokenClient tokenClient;
    private final KeycloakCookieWriter cookies;
    private final KeycloakSessionEventPublisher events;
    private final Clock clock;

    public KeycloakLogoutHandler(KeycloakSessionStore store, TokenCipher cipher, KeycloakTokenClient tokenClient, KeycloakCookieWriter cookies,
                                 KeycloakSessionEventPublisher events, Clock clock) {
        this.store = Objects.requireNonNull(store);
        this.cipher = Objects.requireNonNull(cipher);
        this.tokenClient = Objects.requireNonNull(tokenClient);
        this.cookies = Objects.requireNonNull(cookies);
        this.events = Objects.requireNonNull(events);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<KeycloakSessionRecord> record = cookies.read(request, KeycloakCookie.SESSION)
            .filter(SessionIds::looksLikeSid)
            .flatMap(sid -> store.deleteBySidHash(SessionIds.hash(sid)));
        cookies.clearAll(response);
        Result result = record.map(this::endAndLogoutAtKeycloak).orElse(Result.NO_SESSION);
        request.setAttribute(RESULT_ATTRIBUTE, result);
    }

    /** 이 요청의 로그아웃 결과. 로그아웃 처리기가 돌지 않았으면 {@link Result#NO_SESSION}. */
    public static Result result(HttpServletRequest request) {
        return request.getAttribute(RESULT_ATTRIBUTE) instanceof Result result ? result : Result.NO_SESSION;
    }

    private Result endAndLogoutAtKeycloak(KeycloakSessionRecord record) {
        events.publish(KeycloakSessionEvent.ended(record, KeycloakSessionEndReason.LOGOUT, clock.instant()));
        try {
            tokenClient.logout(cipher.decrypt(record.refreshToken()));
            return Result.KEYCLOAK_LOGGED_OUT;
        } catch (RuntimeException e) {
            log.info("[KSS] Keycloak 로그아웃을 하지 못해 OIDC 로그아웃 주소로 보냅니다 session={} ({})", record.id(), e.getMessage());
            return Result.KEYCLOAK_FAILED;
        }
    }
}
