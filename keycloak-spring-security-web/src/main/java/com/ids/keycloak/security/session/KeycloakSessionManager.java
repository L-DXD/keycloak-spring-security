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

    /**
     * 세션에서 Keycloak Session ID를 삭제합니다 (H-3).
     * <p>
     * 재로그인 시 새 토큰에 {@code sid} 클레임이 없다면, 이전 로그인의 Keycloak Session ID가 세션에
     * 남아 있지 않도록 명시적으로 제거해야 한다(잔여물로 인한 Back-Channel 로그아웃 오탐지 방지).
     * </p>
     *
     * @param session HTTP 세션
     */
    public void removeKeycloakSessionId(HttpSession session) {
        if (session == null) {
            return;
        }
        session.removeAttribute(KEYCLOAK_SESSION_ID_ATTR);
        log.debug("[SessionManager] Keycloak Session ID 삭제 완료.");
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

    /**
     * 세션에 저장된 Principal Name을 조회합니다 (H-3).
     * <p>
     * 재로그인 시 이전 사용자와 새 사용자가 동일한지 판별하는 데 사용된다
     * ({@code KeycloakLoginService} 참고).
     * </p>
     *
     * @param session HTTP 세션
     * @return Principal Name (Optional)
     */
    public Optional<String> getPrincipalName(HttpSession session) {
        if (session == null) {
            return Optional.empty();
        }
        String principalName = (String) session.getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME);
        return Optional.ofNullable(principalName);
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

    // =====================
    // 재로그인 세션 위생 (H-3 / H-C 공통 로직)
    // =====================

    /**
     * 기존 세션의 Principal Name과 새로 인증된 사용자의 Principal Name이 달라 재로그인 잔여물
     * 방지 처리가 필요한지 판별합니다 (H-3 / H-C 공통 로직).
     * <p>
     * {@code changeSessionId()}는 세션 ID만 회전하고 기존 속성(Refresh Token/Keycloak Session ID
     * 등)은 그대로 보존한다. 따라서 기존 세션이 "다른 사용자"의 것이라면(예: 로그아웃 없이 다른
     * 계정으로 재로그인) ID 회전만으로는 이전 사용자의 잔여물이 새 사용자의 세션에 남아, 다음
     * 요청에서 이전 사용자로 재발급·인증되거나 Back-Channel 로그아웃이 엉뚱한 세션을 무효화할
     * 위험이 있다. 이 메서드는 판별만 수행하며, 실제 무효화(예: {@link #invalidateSession})는
     * 호출자가 이 결과를 보고 수행해야 한다.
     * </p>
     * <p>
     * {@code KeycloakLoginService#authenticate}와 {@code OidcLoginSuccessHandler}(H-C)가 이
     * 메서드를 공유해, 두 로그인 경로의 재로그인 잔여물 방지 정책이 서로 갈라지지 않도록 한다.
     * </p>
     *
     * @param existingSession   인증 처리 시작 시점의 기존 세션 (없으면 {@code null})
     * @param newPrincipalName  새로 인증된 사용자의 Principal Name
     * @return 기존 세션이 있고 그 Principal Name이 새 인증과 다르면 {@code true}
     */
    public boolean isDifferentUserReLogin(HttpSession existingSession, String newPrincipalName) {
        if (existingSession == null) {
            return false;
        }
        String previousPrincipalName = getPrincipalName(existingSession).orElse(null);
        return previousPrincipalName != null && !previousPrincipalName.equals(newPrincipalName);
    }

    /**
     * 재로그인 결과(Principal Name/Refresh Token/Keycloak Session ID)를 세션에 동기화합니다
     * (H-3 / H-C 공통 로직).
     * <p>
     * 이번 로그인에 Refresh Token/Keycloak Session ID가 제공되면 저장하고, 제공되지 않으면
     * 이전 로그인(같은 세션에 남아있을 수 있는 값)의 잔여물이 남지 않도록 명시적으로 제거한다.
     * {@code changeSessionId()}는 속성을 보존하므로 이 명시적 제거가 없으면 이전 호출의 값이
     * 계속 유효하게 남는다.
     * </p>
     *
     * @param session        저장 대상 세션 (null이면 아무 것도 하지 않음)
     * @param principalName  이번에 인증된 사용자의 Principal Name
     * @param refreshToken   이번 로그인에서 발급된 Refresh Token (없으면 {@code null})
     * @param keycloakSid    이번 로그인의 Keycloak Session ID(sid 클레임, 없으면 {@code null})
     */
    public void syncReLoginArtifacts(
        HttpSession session, String principalName, String refreshToken, String keycloakSid) {
        if (session == null) {
            return;
        }
        savePrincipalName(session, principalName);
        if (refreshToken != null) {
            saveRefreshToken(session, refreshToken);
        } else {
            removeRefreshToken(session);
        }
        if (keycloakSid != null) {
            saveKeycloakSessionId(session, keycloakSid);
        } else {
            removeKeycloakSessionId(session);
        }
    }
}