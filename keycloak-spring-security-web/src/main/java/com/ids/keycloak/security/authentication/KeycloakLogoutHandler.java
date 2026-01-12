package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * 프론트채널 로그아웃 시 Keycloak 서버에 로그아웃 요청을 보내고,
 * 세션을 무효화하고 토큰 쿠키를 삭제하는 핸들러입니다.
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakLogoutHandler implements LogoutHandler {

    private final KeycloakClient keycloakClient;
    private final KeycloakSessionManager sessionManager;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.debug("[LogoutHandler] 로그아웃 처리를 시작합니다.");

        HttpSession session = request.getSession(false);

        // 1. Keycloak 서버에 로그아웃 요청 (Refresh Token으로)
        if (session != null) {
            String refreshToken = sessionManager.getRefreshToken(session).orElse(null);
            
            if (refreshToken != null) {
                try {
                    keycloakClient.auth().logout(refreshToken);
                    log.debug("[LogoutHandler] Keycloak 서버 로그아웃 요청 완료.");
                } catch (Exception e) {
                    log.warn("[LogoutHandler] Keycloak 서버 로그아웃 요청 실패: {}", e.getMessage());
                }
            } else {
                log.debug("[LogoutHandler] 세션에 Refresh Token이 없습니다.");
            }

            // 2. HTTP 세션 무효화
            sessionManager.invalidateSession(session);
        } else {
            log.debug("[LogoutHandler] 무효화할 세션이 없습니다.");
        }

        // 3. 모든 토큰 관련 쿠키 삭제
        CookieUtil.deleteAllTokenCookies(response);
        log.debug("[LogoutHandler] 토큰 쿠키 삭제 완료.");

        log.debug("[LogoutHandler] 로그아웃 처리 완료.");
    }
}
