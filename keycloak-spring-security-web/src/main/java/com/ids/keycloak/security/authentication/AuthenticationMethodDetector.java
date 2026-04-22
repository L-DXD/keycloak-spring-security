package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

/**
 * HTTP 요청을 분석하여 인증 방식({@link AuthenticationMethod})을 판별하는 클래스입니다.
 * <p>
 * 판별 순서 (우선순위 순):
 * <ol>
 *   <li>{@code Authorization: Bearer } 헤더 → {@link AuthenticationMethod#BEARER}</li>
 *   <li>{@code Authorization: Basic } 헤더 → {@link AuthenticationMethod#BASIC}</li>
 *   <li>POST 메서드 + 설정된 login-paths 경로 → {@link AuthenticationMethod#CREDENTIAL_LOGIN}
 *       (body 파싱 없이 URI + HTTP 메서드만 사용)</li>
 *   <li>{@code access_token} 또는 {@code id_token} 쿠키 존재 → {@link AuthenticationMethod#OIDC_COOKIE}</li>
 *   <li>그 외 → {@link AuthenticationMethod#NONE}</li>
 * </ol>
 * </p>
 */
@Slf4j
public class AuthenticationMethodDetector {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String POST_METHOD = "POST";

    private final List<String> loginPaths;

    /**
     * @param loginPaths Credential(body) 기반 로그인으로 판별할 경로 목록.
     *                   기본값으로 {@code /api/keycloak/login}이 포함되어야 합니다.
     */
    public AuthenticationMethodDetector(List<String> loginPaths) {
        this.loginPaths = loginPaths != null ? List.copyOf(loginPaths) : List.of("/api/keycloak/login");
    }

    /**
     * 요청에서 인증 방식을 판별합니다.
     *
     * @param request HTTP 요청
     * @return 판별된 {@link AuthenticationMethod}
     */
    public AuthenticationMethod detect(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            log.debug("[AuthMethodDetector] Authorization: Bearer 헤더 감지 → BEARER");
            return AuthenticationMethod.BEARER;
        }

        if (authorization != null && authorization.startsWith(BASIC_PREFIX)) {
            log.debug("[AuthMethodDetector] Authorization: Basic 헤더 감지 → BASIC");
            return AuthenticationMethod.BASIC;
        }

        if (isCredentialLoginRequest(request)) {
            log.debug("[AuthMethodDetector] Credential 로그인 경로 감지 → CREDENTIAL_LOGIN (uri={})", request.getRequestURI());
            return AuthenticationMethod.CREDENTIAL_LOGIN;
        }

        if (hasTokenCookie(request)) {
            log.debug("[AuthMethodDetector] OIDC 토큰 쿠키 감지 → OIDC_COOKIE");
            return AuthenticationMethod.OIDC_COOKIE;
        }

        log.debug("[AuthMethodDetector] 판별 불가 → NONE");
        return AuthenticationMethod.NONE;
    }

    private boolean isCredentialLoginRequest(HttpServletRequest request) {
        if (!POST_METHOD.equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String uri = request.getRequestURI();
        for (String loginPath : loginPaths) {
            if (uri.equals(loginPath)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasTokenCookie(HttpServletRequest request) {
        return CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME).isPresent()
            || CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME).isPresent();
    }
}
