package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.AuthenticationMethod;
import com.ids.keycloak.security.authentication.AuthenticationMethodDetector;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.ClientIpResolver;
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
import java.util.List;
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
 * OIDC 쿠키 방식 전용 필터입니다. Bearer/Basic/Credential-Login 등 stateless 인증 방식은
 * {@link AuthenticationMethodDetector}가 감지하여 pass-through 처리하므로 세션을 요구하지 않습니다.
 * </p>
 */
@Slf4j
public class KeycloakAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final KeycloakAuthenticationProvider authenticationProvider;
    private final KeycloakSessionManager sessionManager;
    private final KeycloakClient keycloakClient;
    private final List<String> skipPaths;
    private final AuthenticationMethodDetector methodDetector;

    /**
     * 신뢰 프록시 홉 수. 기본값 0 = XFF 무시, remoteAddr 사용.
     * {@link ClientIpResolver} 참고.
     */
    private int trustedProxyCount = 0;

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient
    ) {
        this(authenticationManager, authenticationProvider, sessionManager, keycloakClient, List.of());
    }

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient,
        List<String> skipPaths
    ) {
        this.authenticationManager = authenticationManager;
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.keycloakClient = keycloakClient;
        this.skipPaths = skipPaths != null ? skipPaths : List.of();
        this.methodDetector = new AuthenticationMethodDetector(List.of("/api/keycloak/login"));
    }

    /**
     * 명시적 login-paths를 주입받는 생성자입니다.
     * {@code KeycloakHttpConfigurer}에서 properties 기반 login-paths를 전달할 때 사용합니다.
     */
    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        KeycloakAuthenticationProvider authenticationProvider,
        KeycloakSessionManager sessionManager,
        KeycloakClient keycloakClient,
        List<String> skipPaths,
        List<String> loginPaths
    ) {
        this.authenticationManager = authenticationManager;
        this.authenticationProvider = authenticationProvider;
        this.sessionManager = sessionManager;
        this.keycloakClient = keycloakClient;
        this.skipPaths = skipPaths != null ? skipPaths : List.of();
        this.methodDetector = new AuthenticationMethodDetector(loginPaths);
    }

    /**
     * 신뢰 프록시 홉 수를 설정합니다.
     * {@code KeycloakHttpConfigurer}에서 {@code keycloak.security.trusted-proxy-count} 값을 주입합니다.
     *
     * @param trustedProxyCount 신뢰 프록시 홉 수 (0: XFF 무시, -1: 레거시 동작, N>0: 홉 기반 파싱)
     */
    public void setTrustedProxyCount(int trustedProxyCount) {
        this.trustedProxyCount = trustedProxyCount;
    }

    /**
     * 명시적으로 등록된 skipPaths에 해당하는 경로만 필터를 건너뜁니다.
     * 인증 방식별 분기는 {@link #doFilterInternal}의 {@link AuthenticationMethodDetector}가 담당합니다.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        for (String skipPath : skipPaths) {
            if (path.equals(skipPath)) {
                log.debug("[Filter] 토큰 API 경로 '{}' — 필터 스킵", path);
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // 인증 방식 판별 — 진입부에서 단일 판별, 이후 분기
        AuthenticationMethod method = methodDetector.detect(request);

        switch (method) {
            case BEARER, BASIC, CREDENTIAL_LOGIN -> {
                AuthenticationEventLogger.logSkipped(method.name(), getClientIp(request), "stateless 인증 경로");
                filterChain.doFilter(request, response);
                return;
            }
            case NONE -> {
                filterChain.doFilter(request, response);
                return;
            }
            case OIDC_COOKIE -> handleOidcCookieAuth(request, response, filterChain);
        }
    }

    /**
     * OIDC 쿠키 기반 인증을 처리합니다.
     * 세션 없음은 예외가 아닌 정상 비로그인 상태로 처리합니다.
     */
    private void handleOidcCookieAuth(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // 이미 인증된 경우 스킵 (Basic Auth 등 선행 필터에서 인증 완료)
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()
                && !(existingAuth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            log.debug("[Filter] 이미 인증된 사용자 '{}' — OIDC 쿠키 인증 스킵.", existingAuth.getName());
            filterChain.doFilter(request, response);
            return;
        }

        String idTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME).orElse(null);
        String accessTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME).orElse(null);

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                // 세션 없음은 정상 비로그인 상태 — 예외 발생 없이 pass-through
                AuthenticationEventLogger.logNoSession(
                    AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request));
                CookieUtil.deleteAllTokenCookies(response);
                filterChain.doFilter(request, response);
                return;
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
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                principal, idTokenValue, accessTokenValue, false);
            log.debug("[Filter] 인증 전 Authentication 객체 생성: {}", principal.getName());

            Authentication successfulAuthentication;
            try {
                log.debug("[Filter] AuthenticationManager에 인증 위임...");
                successfulAuthentication = authenticationManager.authenticate(authRequest);
                log.debug("[Filter] 인증 성공: {}", successfulAuthentication.getName());

            } catch (IntrospectionFailedException | NullPointerException | UserInfoFetchException e) {
                log.warn("[Filter] 온라인 검증 실패, Refresh Token으로 재발급 시도. 원인: {}", e.getMessage());
                successfulAuthentication = refreshAndAuthenticate(session, response, refreshToken);
            }

            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(successfulAuthentication);
            log.debug("[Filter] SecurityContext에 인증된 사용자 '{}' 등록 완료.", successfulAuthentication.getName());
            AuthenticationEventLogger.logSuccess(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), successfulAuthentication.getName());

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증에 실패했습니다: {}", e.getMessage());
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown", e.getMessage());
            CookieUtil.deleteAllTokenCookies(response);
            sessionManager.invalidateSession(request.getSession());
        } catch (Exception e) {
            // 예기치 못한 예외 — warn 레벨로 기록하되 stacktrace 유지
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증 과정에서 예상치 못한 오류가 발생했습니다.", e);
            AuthenticationEventLogger.logFailure(
                AuthenticationEventLogger.METHOD_OIDC_COOKIE, getClientIp(request), "unknown", e.getMessage());
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

        if (newTokens.getRefreshToken() != null) {
            sessionManager.saveRefreshToken(session, newTokens.getRefreshToken());
        }

        updateCookies(response, newTokens);

        log.debug("[Filter] 재발급된 토큰으로 인증 객체 생성.");
        return authenticationProvider.createAuthenticatedToken(newTokens.getIdToken(), newTokens.getAccessToken());
    }

    /**
     * Refresh Token을 사용하여 새로운 토큰을 발급받습니다.
     *
     * @param refreshToken Refresh Token
     * @return 새로 발급된 토큰 정보
     * @throws RefreshTokenException         Refresh Token이 만료되었거나 유효하지 않은 경우
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

    private String getClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(
            request.getHeader("X-Forwarded-For"),
            request.getRemoteAddr(),
            trustedProxyCount
        );
    }

    private KeycloakPrincipal createPrincipalFromIdToken(String idToken) {
        String subject = JwtUtil.parseSubjectWithoutValidation(idToken);
        if (subject == null || subject.isBlank()) {
            subject = "unknown";
        }
        return new KeycloakPrincipal(subject, Collections.emptyList(), null, null);
    }
}
