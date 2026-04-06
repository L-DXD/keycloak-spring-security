
package com.ids.keycloak.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import com.ids.keycloak.security.util.SecurityHandlerUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * 인증(Authentication) 과정에서 실패하는 경우 호출되는 핸들러 KeycloakSecurityException 예외를 캐치하여 ErrorCode에 맞는 HTTP 응답을 생성
 */
@Slf4j
public class KeycloakAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final KeycloakErrorProperties errorProperties;
    private final boolean basicAuthEnabled;
    private final String realmName;
    private final BearerTokenAuthenticationEntryPoint bearerTokenEntryPoint = new BearerTokenAuthenticationEntryPoint();

    /**
     * 기존 생성자 (하위 호환성 유지).
     */
    public KeycloakAuthenticationEntryPoint(ObjectMapper objectMapper, KeycloakErrorProperties errorProperties) {
        this(objectMapper, errorProperties, false, null);
    }

    /**
     * Basic Auth + Bearer Token 지원을 위한 확장 생성자.
     */
    public KeycloakAuthenticationEntryPoint(
        ObjectMapper objectMapper,
        KeycloakErrorProperties errorProperties,
        boolean basicAuthEnabled,
        String realmName
    ) {
        this.objectMapper = objectMapper;
        this.errorProperties = errorProperties;
        this.basicAuthEnabled = basicAuthEnabled;
        this.realmName = realmName;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
        throws IOException, ServletException {
        // Bearer Token 요청인 경우 BearerTokenAuthenticationEntryPoint에 위임
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            log.debug("KeycloakAuthenticationEntryPoint: Bearer Token 요청 감지 - BearerTokenAuthenticationEntryPoint로 위임");
            bearerTokenEntryPoint.commence(request, response, authException);
            return;
        }

        // KeycloakSecurityException이 원인인 경우, 해당 예외에서 errorCode를 추출
        if (authException.getCause() instanceof KeycloakSecurityException cause) {
            log.debug("KeycloakAuthenticationEntryPoint: 인증 실패 - KeycloakSecurityException 발생 = {}, {}",
                cause.getErrorCode(), cause.getMessage());
        }

        // Basic Auth 요청인 경우 WWW-Authenticate 헤더 추가
        if (basicAuthEnabled && isBasicAuthRequest(request)) {
            String realm = (realmName != null) ? realmName : "keycloak";
            response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        }

        // 페이지 이동 모드: true 시 브라우저 주소창을 실패 URL로 리다이렉트 (HTML 렌더링 환경)
        if (errorProperties.isRedirectEnabled()) {
            // AJAX 요청이고 ajaxReturnsJson이 true면 JSON 응답
            if (errorProperties.isAjaxReturnsJson() && SecurityHandlerUtil.isAjaxRequest(request)) {
                log.debug("KeycloakAuthenticationEntryPoint: AJAX 요청 - JSON 응답 반환");
                SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.AUTHENTICATION_FAILED);
                return;
            }

            // 세션 만료 여부 확인
            String redirectUrl = determineRedirectUrl(request);
            log.debug("KeycloakAuthenticationEntryPoint: 인증 실패 - 리다이렉트 URL: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return;
        }

        // API 모드: 기본 401 JSON 응답
        SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.AUTHENTICATION_FAILED);
    }

    /**
     * 세션 만료 여부에 따라 리다이렉트 URL을 결정합니다.
     */
    private String determineRedirectUrl(HttpServletRequest request) {
        // 세션이 존재했으나 만료된 경우 (requestedSessionId가 있지만 유효하지 않음)
        if (isSessionExpired(request)) {
            log.debug("KeycloakAuthenticationEntryPoint: 세션 만료 감지");
            return errorProperties.getEffectiveSessionExpiredRedirectUrl();
        }
        return errorProperties.getAuthenticationFailedRedirectUrl();
    }

    /**
     * 세션이 만료되었는지 확인합니다.
     * 요청에 세션 ID가 있지만 유효하지 않은 경우 세션이 만료된 것으로 판단합니다.
     */
    private boolean isSessionExpired(HttpServletRequest request) {
        String requestedSessionId = request.getRequestedSessionId();
        if (requestedSessionId != null) {
            HttpSession session = request.getSession(false);
            // 세션 ID가 요청에 있었지만 현재 유효한 세션이 없는 경우
            return session == null || !request.isRequestedSessionIdValid();
        }
        return false;
    }

    /**
     * Basic Auth 요청인지 확인합니다.
     */
    private boolean isBasicAuthRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        return authHeader != null && authHeader.startsWith("Basic ");
    }
}
