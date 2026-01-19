package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.model.PreAuthenticationPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP 요청의 쿠키에서 Keycloak 토큰을 읽어 인증을 시도하는 필터입니다.
 * HTTP Session에서 Refresh Token을 조회하여 토큰 재발급에 사용합니다.
 */
@Slf4j
public class KeycloakAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final KeycloakSessionManager sessionManager;

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakSessionManager sessionManager
    ) {
        this.authenticationManager = authenticationManager;
        this.sessionManager = sessionManager;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException
    {
        String idTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME).orElse(null);
        String accessTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME).orElse(null);

        try {
            // HTTP Session에서 Refresh Token 가져오기
            HttpSession session = request.getSession(false);
            if (session == null) {
                log.debug("[Filter] HTTP Session이 없음 (로그아웃 상태) - 쿠키 삭제 후 다음 필터로 진행");
                throw new AuthenticationFailedException("HTTP Session이 없음");
            }

            String refreshToken = sessionManager.getRefreshToken(session).orElse(null);
            if (refreshToken == null) {
                log.debug("[Filter] HTTP Session에 Refresh Token이 없음 - 쿠키 삭제 후 다음 필터로 진행");
                CookieUtil.deleteAllTokenCookies(response);
                filterChain.doFilter(request, response);
                return;
            }

            log.debug("[Filter] HTTP Session에서 Refresh Token 로드 성공.");

            PreAuthenticationPrincipal principal = createPrincipalFromIdToken(idTokenValue);
            KeycloakAuthentication authRequest = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue);
            authRequest.setDetails(refreshToken);  // Refresh Token을 details에 설정
            log.debug("[Filter] 인증 전 Authentication 객체 생성: {}", principal.getName());

            // 인증 수행
            log.debug("[Filter] AuthenticationManager에 인증 위임...");
            Authentication successfulAuthentication = authenticationManager.authenticate(authRequest);
            log.debug("[Filter] 인증 성공: {}", successfulAuthentication.getName());

            // 토큰 재발급 처리
            if (successfulAuthentication.getDetails() instanceof KeycloakTokenInfo newTokens) {
                log.debug("[Filter] 토큰 재발급 감지. 세션 및 쿠키 업데이트.");

                // 새로운 Refresh Token을 세션에 저장
                if (newTokens.getRefreshToken() != null) {
                    sessionManager.saveRefreshToken(session, newTokens.getRefreshToken());
                }

                // 쿠키 업데이트
                updateCookies(response, newTokens);
            }

            // SecurityContext에 인증 정보 설정 (요청 처리 중에만 유효)
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(successfulAuthentication);
            log.debug("[Filter] SecurityContext에 인증된 사용자 '{}' 등록 완료.", successfulAuthentication.getName());

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증에 실패했습니다: {}", e.getMessage());
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            log.error("[Filter] Keycloak 인증 과정에서 예상치 못한 오류가 발생했습니다.", e);
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        }

        filterChain.doFilter(request, response);
    }

    private void updateCookies(HttpServletResponse response, KeycloakTokenInfo newTokens) {
        log.debug("[Filter] 토큰이 재발급되어 쿠키를 업데이트합니다.");
        int maxAge = newTokens.getExpireTime();
        CookieUtil.addTokenCookies(response, newTokens.getAccessToken(), maxAge, newTokens.getIdToken(), maxAge);
    }

    private PreAuthenticationPrincipal createPrincipalFromIdToken(String idToken) {
        // 서명 검증 없이 subject만 추출 (온라인 검증에서 유효성 확인)
        String subject = JwtUtil.parseSubjectWithoutValidation(idToken);
        if (subject == null || subject.isBlank()) {
            return new PreAuthenticationPrincipal("unknown");
        }
        return new PreAuthenticationPrincipal(subject);
    }
}