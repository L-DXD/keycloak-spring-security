package com.ids.keycloak.security.session;

import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

/**
 * Keycloak 인증 관련 세션 데이터를 관리하는 매니저 클래스입니다.
 * <p>
 * 다음 데이터를 세션에 저장/조회/삭제합니다:
 * <ul>
 *   <li>Refresh Token - 토큰 갱신에 사용</li>
 *   <li>Keycloak Session ID (sid) - Back-Channel 로그아웃에 사용</li>
 *   <li>Principal Name - 세션 검색에 사용</li>
 * </ul>
 * </p>
 */
@Slf4j
public class KeycloakSessionManager {

    /** 세션에 Refresh Token을 저장하기 위한 키 */
    public static final String REFRESH_TOKEN_ATTR = "KEYCLOAK_REFRESH_TOKEN";

    /** 세션에 Keycloak Session ID를 저장하기 위한 키 */
    public static final String KEYCLOAK_SESSION_ID_ATTR = "KEYCLOAK_SESSION_ID";

    // =====================
    // Refresh Token 관련
    // =====================

    /**
     * 세션에 Refresh Token을 저장합니다.
     *
     * @param session      HTTP 세션
     * @param refreshToken 저장할 Refresh Token
     */
    public void saveRefreshToken(HttpSession session, String refreshToken) {
        if (session == null || refreshToken == null) {
            log.warn("[SessionManager] 세션 또는 Refresh Token이 null입니다.");
            return;
        }
        session.setAttribute(REFRESH_TOKEN_ATTR, refreshToken);
        log.debug("[SessionManager] Refresh Token 저장 완료.");
    }

    /**
     * 세션에서 Refresh Token을 조회합니다.
     *
     * @param session HTTP 세션
     * @return Refresh Token (Optional)
     */
    public Optional<String> getRefreshToken(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        String refreshToken = (String) session.getAttribute(REFRESH_TOKEN_ATTR);
        return Optional.ofNullable(refreshToken);
    }

    /**
     * 세션에서 Refresh Token을 삭제합니다.
     *
     * @param session HTTP 세션
     */
    public void removeRefreshToken(HttpSession session) {
        if (session == null) {
            return;
        }
        session.removeAttribute(REFRESH_TOKEN_ATTR);
        log.debug("[SessionManager] Refresh Token 삭제 완료.");
    }

    // =====================
    // Keycloak Session ID 관련
    // =====================

    /**
     * 세션에 Keycloak Session ID (sid)를 저장합니다.
     *
     * @param session           HTTP 세션
     * @param keycloakSessionId Keycloak의 세션 ID (sid 클레임)
     */
    public void saveKeycloakSessionId(HttpSession session, String keycloakSessionId) {
        if (session == null || keycloakSessionId == null) {
            return;
        }
        session.setAttribute(KEYCLOAK_SESSION_ID_ATTR, keycloakSessionId);
        log.debug("[SessionManager] Keycloak Session ID 저장: {}", keycloakSessionId);
    }

    /**
     * 세션에서 Keycloak Session ID를 조회합니다.
     *
     * @param session HTTP 세션
     * @return Keycloak Session ID (Optional)
     */
    public Optional<String> getKeycloakSessionId(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        String sid = (String) session.getAttribute(KEYCLOAK_SESSION_ID_ATTR);
        return Optional.ofNullable(sid);
    }

    // =====================
    // Principal Name 관련
    // =====================

    /**
     * 세션에 Principal Name을 저장합니다.
     * Back-Channel 로그아웃 시 세션 검색에 사용됩니다.
     *
     * @param session       HTTP 세션
     * @param principalName 사용자 식별자
     */
    public void savePrincipalName(HttpSession session, String principalName) {
        if (session == null || principalName == null) {
            return;
        }
        session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, principalName);
        log.debug("[SessionManager] Principal Name 저장: {}", principalName);
    }

    // =====================
    // 세션 무효화
    // =====================

    /**
     * 세션을 무효화합니다.
     *
     * @param session HTTP 세션
     */
    public void invalidateSession(HttpSession session) {
        if (session == null) {
            log.debug("[SessionManager] 무효화할 세션이 없습니다.");
            return;
        }
        String sessionId = session.getId();
        session.invalidate();
        log.debug("[SessionManager] 세션 무효화 완료. Session ID: {}", sessionId);
    }
}