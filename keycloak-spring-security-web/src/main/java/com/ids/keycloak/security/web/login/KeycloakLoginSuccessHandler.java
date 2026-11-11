package com.ids.keycloak.security.web.login;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.event.KeycloakSessionEventPublisher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.token.RefreshTokens;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그인 성공 (LOGIN-03·06·07): 세션 행을 만들고 sid·at·csrf 쿠키를 쓴 뒤 화면 주소로 302.
 * <ol>
 *   <li>액세스 토큰을 로컬 검증 규칙으로 한 번 더 본다 (sub, sid가 있어야 한다)</li>
 *   <li>예전 sid 쿠키가 있으면 그 행을 지운다 (세션 고정 방지)</li>
 *   <li>새 sid(256비트 난수)를 만들고 행에는 SHA-256과 암호화한 리프레시 토큰만 둔다. ID 토큰은 어디에도 두지 않는다</li>
 *   <li>at 쿠키 수명은 토큰 남은 시간, sid·csrf는 절대 상한까지</li>
 * </ol>
 * 실패하면 {@link KeycloakLoginFailureHandler}로 넘긴다. 세션 행은 만들지 않는다.
 */
public class KeycloakLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(KeycloakLoginSuccessHandler.class);

    private final KeycloakAccessTokenValidator validator;
    private final KeycloakSessionStore store;
    private final TokenCipher cipher;
    private final KeycloakCsrfTokenSigner csrf;
    private final KeycloakCookieWriter cookies;
    private final KeycloakSessionEventPublisher events;
    private final AuthenticationFailureHandler failureHandler;
    private final Clock clock;
    private final Duration absoluteTimeout;
    private final URI frontendBaseUrl;

    public KeycloakLoginSuccessHandler(KeycloakAccessTokenValidator validator, KeycloakSessionStore store, TokenCipher cipher,
                                       KeycloakCsrfTokenSigner csrf, KeycloakCookieWriter cookies, KeycloakSessionEventPublisher events,
                                       AuthenticationFailureHandler failureHandler, Clock clock, Duration absoluteTimeout,
                                       URI frontendBaseUrl) {
        this.validator = Objects.requireNonNull(validator);
        this.store = Objects.requireNonNull(store);
        this.cipher = Objects.requireNonNull(cipher);
        this.csrf = Objects.requireNonNull(csrf);
        this.cookies = Objects.requireNonNull(cookies);
        this.events = Objects.requireNonNull(events);
        this.failureHandler = Objects.requireNonNull(failureHandler);
        this.clock = Objects.requireNonNull(clock);
        this.absoluteTimeout = Objects.requireNonNull(absoluteTimeout);
        this.frontendBaseUrl = Objects.requireNonNull(frontendBaseUrl);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {
        OAuth2AuthorizedClient client = KeycloakLoginAuthorizedClientRepository.current(request);
        if (client == null || client.getRefreshToken() == null) {
            log.warn("[KSS] Keycloak이 리프레시 토큰을 주지 않았습니다. client의 Standard flow와 scope를 확인하세요");
            fail(request, response, "login_failed");
            return;
        }
        OAuth2AccessToken accessToken = client.getAccessToken();
        AccessTokenValidationResult result = validator.validate(accessToken.getTokenValue());
        if (!result.isValid()) {
            log.warn("[KSS] 로그인으로 받은 액세스 토큰이 검증 규칙에 맞지 않습니다: {}", result.reason());
            fail(request, response, "invalid_token");
            return;
        }
        if (isBlank(result.subject()) || isBlank(result.sessionId())) {
            log.warn("[KSS] 액세스 토큰에 sub 또는 sid가 없습니다. Keycloak client scope 'basic'(sub, sid mapper)을 확인하세요");
            fail(request, response, "invalid_token");
            return;
        }

        Instant now = clock.instant();
        endPreviousSession(request, now);

        String sid = SessionIds.newSid();
        Instant absoluteExpiresAt = now.plus(absoluteTimeout);
        KeycloakSessionRecord record = new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), result.subject(),
            result.sessionId(), cipher.encrypt(client.getRefreshToken().getTokenValue()),
            refreshExpiresAt(client.getRefreshToken(), absoluteExpiresAt), now, absoluteExpiresAt, null);
        store.insert(record);
        events.publish(KeycloakSessionEvent.created(record, now));

        writeCookies(response, sid, accessToken, now, absoluteExpiresAt);
        String target = redirectUrl(returnPath(request));
        log.debug("[KSS] 로그인 성공, 화면으로 보냅니다: {}", target);
        response.sendRedirect(target);
    }

    /** 예전 sid 쿠키가 가리키는 행을 지운다 (LOGIN-06). */
    protected void endPreviousSession(HttpServletRequest request, Instant now) {
        cookies.read(request, KeycloakCookie.SESSION)
            .filter(SessionIds::looksLikeSid)
            .flatMap(previous -> store.deleteBySidHash(SessionIds.hash(previous)))
            .ifPresent(previous -> events.publish(KeycloakSessionEvent.ended(previous, KeycloakSessionEndReason.RELOGIN, now)));
    }

    /** sid·at·csrf 쿠키 (COOKIE-01·03). */
    protected void writeCookies(HttpServletResponse response, String sid, OAuth2AccessToken accessToken, Instant now,
                                Instant absoluteExpiresAt) {
        Duration untilAbsolute = Duration.between(now, absoluteExpiresAt);
        Duration untilTokenExpiry = accessToken.getExpiresAt() == null ? untilAbsolute : Duration.between(now, accessToken.getExpiresAt());
        cookies.write(response, KeycloakCookie.SESSION, sid, untilAbsolute);
        cookies.write(response, KeycloakCookie.ACCESS_TOKEN, accessToken.getTokenValue(),
            untilTokenExpiry.compareTo(untilAbsolute) < 0 ? untilTokenExpiry : untilAbsolute);
        cookies.write(response, KeycloakCookie.CSRF, csrf.create(sid), untilAbsolute);
    }

    /** 리프레시 토큰 만료. 읽지 못하면 절대 상한. */
    protected Instant refreshExpiresAt(OAuth2RefreshToken refreshToken, Instant absoluteExpiresAt) {
        if (refreshToken.getExpiresAt() != null) {
            return refreshToken.getExpiresAt();
        }
        return RefreshTokens.expiresAt(refreshToken.getTokenValue()).orElse(absoluteExpiresAt);
    }

    /** 화면 주소 + 돌아갈 경로. */
    protected String redirectUrl(String returnPath) {
        String base = frontendBaseUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + returnPath;
    }

    private static String returnPath(HttpServletRequest request) {
        return request.getAttribute(KeycloakAuthorizationRequestRepository.RETURN_PATH_ATTRIBUTE) instanceof String path ? path : "/";
    }

    private void fail(HttpServletRequest request, HttpServletResponse response, String code) throws IOException, ServletException {
        failureHandler.onAuthenticationFailure(request, response, new OAuth2AuthenticationException(new OAuth2Error(code)));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
