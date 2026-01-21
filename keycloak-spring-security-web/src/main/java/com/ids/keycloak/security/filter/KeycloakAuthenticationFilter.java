package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestClientException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP 요청의 쿠키에서 Keycloak 토큰을 읽어 인증을 시도하는 필터입니다.
 * HTTP Session에서 Refresh Token을 조회하여 토큰 재발급에 사용합니다.
 * <p>
 * 온라인 검증 실패 시 Refresh Token을 사용하여 토큰을 재발급받고,
 * 재발급된 토큰으로 직접 인증 객체를 생성합니다.
 * </p>
 */
@Slf4j
public class KeycloakAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final KeycloakAuthenticationProvider authenticationProvider;
    private final KeycloakSessionManager sessionManager;
    private final KeycloakClient keycloakClient;

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient
    ) {
        this.authenticationManager = authenticationManager;
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.keycloakClient = keycloakClient;
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

            KeycloakPrincipal principal = createPrincipalFromIdToken(idTokenValue);
            KeycloakAuthentication authRequest = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue, false);
            log.debug("[Filter] 인증 전 Authentication 객체 생성: {}", principal.getName());

            Authentication successfulAuthentication;
            try {
                // 인증 수행 (온라인 검증)
                log.debug("[Filter] AuthenticationManager에 인증 위임...");
                successfulAuthentication = authenticationManager.authenticate(authRequest);
                log.debug("[Filter] 인증 성공: {}", successfulAuthentication.getName());

            } catch (IntrospectionFailedException | NullPointerException e) {
                // 온라인 검증 실패 또는 토큰 파싱 실패 시 Refresh Token으로 재발급 시도
                log.warn("[Filter] 온라인 검증 실패, Refresh Token으로 재발급 시도. 원인: {}", e.getMessage());
                successfulAuthentication = refreshAndAuthenticate(session, response, refreshToken);
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

    /**
     * Refresh Token을 사용하여 토큰을 재발급받고, 인증 객체를 생성합니다.
     * 재발급된 토큰으로 세션과 쿠키를 업데이트합니다.
     *
     * @param session      HTTP Session
     * @param response     HTTP Response (쿠키 업데이트용)
     * @param refreshToken Refresh Token
     * @return 인증된 Authentication 객체
     */
    private Authentication refreshAndAuthenticate(HttpSession session, HttpServletResponse response, String refreshToken) {
        log.debug("[Filter] Keycloak에 토큰 재발급 요청...");

        KeycloakTokenInfo newTokens = refreshTokens(refreshToken);
        log.debug("[Filter] 토큰 재발급 성공. 세션 및 쿠키 업데이트.");

        // 새로운 Refresh Token을 세션에 저장
        if (newTokens.getRefreshToken() != null) {
            sessionManager.saveRefreshToken(session, newTokens.getRefreshToken());
        }

        // 쿠키 업데이트
        updateCookies(response, newTokens);

        // Provider를 통해 인증 객체 생성 (검증 없이 토큰 정보로 Principal 생성)
        log.debug("[Filter] 재발급된 토큰으로 인증 객체 생성.");
        return authenticationProvider.createAuthenticatedToken(newTokens.getIdToken(), newTokens.getAccessToken());
    }

    /**
     * Refresh Token을 사용하여 새로운 토큰을 발급받습니다.
     *
     * @param refreshToken Refresh Token
     * @return 새로 발급된 토큰 정보
     * @throws RefreshTokenException Refresh Token이 만료되었거나 유효하지 않은 경우
     * @throws AuthenticationFailedException 그 외 인증 실패
     */
    private KeycloakTokenInfo refreshTokens(String refreshToken) {
        try {
            KeycloakResponse<KeycloakTokenInfo> response = keycloakClient.auth().reissueToken(refreshToken);
            int status = response.getStatus();

            return switch (status) {
                case 200 -> {
                    log.debug("[Filter] 토큰 재발급 성공.");
                    yield response.getBody()
                        .orElseThrow(() -> new RefreshTokenException("토큰 재발급 실패: 응답 본문이 없습니다."));
                }
                case 401 -> {
                    log.warn("[Filter] Refresh Token이 만료되었거나 유효하지 않습니다.");
                    throw new RefreshTokenException("Refresh Token이 만료되었거나 유효하지 않습니다.");
                }
                default -> {
                    log.error("[Filter] 토큰 재발급 중 예상치 못한 응답. 상태 코드: {}", status);
                    throw new AuthenticationFailedException("토큰 재발급 실패. 상태 코드: " + status);
                }
            };
        } catch (RestClientException e) {
            log.error("[Filter] Keycloak 서버와 통신 중 오류 발생: {}", e.getMessage());
            throw new AuthenticationFailedException("Keycloak 서버와 통신할 수 없습니다: " + e.getMessage());
        }
    }

    private void updateCookies(HttpServletResponse response, KeycloakTokenInfo newTokens) {
        log.debug("[Filter] 토큰이 재발급되어 쿠키를 업데이트합니다.");
        int maxAge = newTokens.getExpireTime();
        CookieUtil.addTokenCookies(response, newTokens.getAccessToken(), maxAge, newTokens.getIdToken(), maxAge);
    }

    private KeycloakPrincipal createPrincipalFromIdToken(String idToken) {
        // 서명 검증 없이 subject만 추출 (온라인 검증에서 유효성 확인)
        String subject = JwtUtil.parseSubjectWithoutValidation(idToken);
        if (subject == null || subject.isBlank()) {
            subject = "unknown";
        }
        // 인증 전이므로 빈 authorities와 attributes로 생성
        return new KeycloakPrincipal(subject, Collections.emptyList(), Collections.emptyMap());
    }
}