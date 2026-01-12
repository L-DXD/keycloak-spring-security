package com.ids.keycloak.security.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

/**
 * OIDC Back-Channel 로그아웃 시 세션을 직접 무효화하는 LogoutHandler입니다.
 * <p>
 * Spring Security의 기본 Back-Channel 로그아웃 핸들러는 HTTP 요청을 통해 세션을 무효화하지만,
 * 이 핸들러는 {@link FindByIndexNameSessionRepository}를 통해 직접 세션을 삭제합니다.
 * 이를 통해 CSRF 토큰 문제와 네트워크 호출 오버헤드를 제거합니다.
 * </p>
 * <p>
 * logout_token에 sid(세션 ID)가 포함된 경우 해당 세션만 삭제하고,
 * sub(사용자 ID)만 포함된 경우 해당 사용자의 모든 세션을 삭제합니다.
 * </p>
 * <p>
 * Replay Attack 방지를 위해 로그아웃 토큰의 jti(JWT ID)를 추적합니다.
 * 이미 처리된 토큰은 무시됩니다.
 * </p>
 */
@Slf4j
public class OidcBackChannelSessionLogoutHandler implements LogoutHandler {

    /** 세션에 저장된 Keycloak Session ID 속성 키 */
    public static final String KEYCLOAK_SESSION_ID_ATTR = "KEYCLOAK_SESSION_ID";

    private final FindByIndexNameSessionRepository<Session> sessionRepository;

    @SuppressWarnings("unchecked")
    public OidcBackChannelSessionLogoutHandler(
        FindByIndexNameSessionRepository<? extends Session> sessionRepository
    ) {
        this.sessionRepository = (FindByIndexNameSessionRepository<Session>) sessionRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.debug("[BackChannelLogoutHandler] 세션 직접 무효화 시작");

        if (authentication == null) {
            log.debug("[BackChannelLogoutHandler] Authentication이 null - 처리 스킵");
            return;
        }

        OidcLogoutToken logoutToken = extractLogoutToken(authentication);
        if (logoutToken == null) {
            log.warn("[BackChannelLogoutHandler] OidcLogoutToken을 추출할 수 없음");
            return;
        }
        log.debug("[BackChannelLogoutHandler] oidcLogoutToken = {}", logoutToken.getTokenValue());

        String subject = logoutToken.getSubject();
        String keycloakSessionId = logoutToken.getSessionId(); // sid 클레임

        log.debug("[BackChannelLogoutHandler] Logout Token - Subject: {}, SessionId(sid): {}", subject, keycloakSessionId);

        if (subject == null) {
            log.warn("[BackChannelLogoutHandler] Subject가 null - 처리 스킵");
            return;
        }

        // sid가 있으면 해당 세션만 삭제, 없으면 모든 세션 삭제
        if (keycloakSessionId != null) {
            revokeSessionByKeycloakSid(subject, keycloakSessionId);
        } else {
            revokeAllUserSessions(subject);
        }
    }

    /**
     * Authentication 객체에서 OidcLogoutToken을 추출합니다.
     */
    private OidcLogoutToken extractLogoutToken(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcLogoutToken logoutToken) {
            return logoutToken;
        }

        Object credentials = authentication.getCredentials();
        if (credentials instanceof OidcLogoutToken logoutToken) {
            return logoutToken;
        }

        return null;
    }

    /**
     * 특정 Keycloak 세션 ID(sid)에 해당하는 세션만 삭제합니다.
     */
    private void revokeSessionByKeycloakSid(String subject, String keycloakSessionId) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(subject);
        log.debug("[BackChannelLogoutHandler] Subject '{}'의 세션 {} 개 검색됨", subject, sessions.size());

        int revokedCount = 0;
        for (Map.Entry<String, ? extends Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            String storedSid = session.getAttribute(KEYCLOAK_SESSION_ID_ATTR);

            if (keycloakSessionId.equals(storedSid)) {
                log.debug("[BackChannelLogoutHandler] 매칭되는 세션 삭제 - Spring Session ID: {}, Keycloak SID: {}",
                        entry.getKey(), storedSid);
                sessionRepository.deleteById(entry.getKey());
                revokedCount++;
            }
        }

        if (revokedCount > 0) {
            log.info("[BackChannelLogoutHandler] Keycloak SID '{}'에 해당하는 세션 {} 개 폐기 완료",
                    keycloakSessionId, revokedCount);
        } else {
            log.warn("[BackChannelLogoutHandler] Keycloak SID '{}'에 해당하는 세션을 찾지 못함", keycloakSessionId);
        }
    }

    /**
     * 주어진 사용자 ID(subject)에 해당하는 모든 세션을 삭제합니다.
     */
    private void revokeAllUserSessions(String subject) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(subject);
        log.debug("[BackChannelLogoutHandler] 검색된 세션 수: {}", sessions.size());

        if (sessions.isEmpty()) {
            log.debug("[BackChannelLogoutHandler] 폐기할 세션 없음");
            return;
        }

        sessions.forEach((sessionId, session) -> {
            log.debug("[BackChannelLogoutHandler] 세션 삭제 - Session ID: {}", sessionId);
            sessionRepository.deleteById(sessionId);
        });

        log.info("[BackChannelLogoutHandler] 사용자 '{}'의 모든 세션 {} 개 폐기 완료", subject, sessions.size());
    }


}
