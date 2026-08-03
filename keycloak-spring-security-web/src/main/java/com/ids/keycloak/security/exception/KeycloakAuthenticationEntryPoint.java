
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
        // (항목 6: 이 EntryPoint는 인증 실패의 최종 처리 지점이므로, 사유가 debug에만 남으면 운영
        // 기본 로그 레벨(INFO)에서는 401 응답의 원인을 전혀 추적할 수 없다. 구조화된 사유 1줄을
        // INFO로 남긴다 — 401 자체는 정상적인 보호 동작이므로 WARN까지는 올리지 않는다.)
        String errorCode = (authException.getCause() instanceof KeycloakSecurityException cause)
            ? cause.getErrorCode().getCode()
            : ErrorCode.AUTHENTICATION_FAILED.getCode();
        log.info("KeycloakAuthenticationEntryPoint: 인증 실패 - uri={}, errorCode={}",
            request.getRequestURI(), errorCode);

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

        // C-1 (회귀 수정): redirectEnabled=false(API 모드, 기본값) 상태에서도, 이 EntryPoint가
        // exceptionHandling에 등록되면 oauth2Login이 기본 제공하던 "브라우저 요청 → 로그인 페이지
        // 리다이렉트" 동작이 완전히 가려진다. Authorization: Basic 헤더를 직접 실은 요청(이 기능이
        // basicAuthEnabled=false로 꺼져 있어도 마찬가지)과 AJAX/명시적 JSON 요청이 아닌(즉 브라우저의
        // HTML 네비게이션으로 보이는) 요청만 기본적으로 authorization endpoint로 리다이렉트해 기존 SSO
        // 로그인 플로우를 그대로 유지한다. Authorization 헤더 보유 자체가 "프로그래밍적 클라이언트"의
        // 근거이므로 basicAuthEnabled 토글과 무관하게 리다이렉트 대상에서 제외한다.
        // oauth2LoginRedirectEnabled=false로 끄면 항상 401 JSON을 반환한다(순수 API 서버).
        if (errorProperties.isOauth2LoginRedirectEnabled()
            && !isBasicAuthRequest(request)
            && !SecurityHandlerUtil.isAjaxRequest(request)) {
            String authorizationUrl = buildOAuth2AuthorizationUrl();
            log.debug("KeycloakAuthenticationEntryPoint: 인증 실패 - OAuth2 로그인으로 리다이렉트: {}", authorizationUrl);
            response.sendRedirect(authorizationUrl);
            return;
        }

        // API 모드: 기본 401 JSON 응답
        SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.AUTHENTICATION_FAILED);
    }

    /**
     * OAuth2 로그인 authorization endpoint URL을 생성합니다 (C-1).
     * <p>
     * Spring Security {@code oauth2Login}의 기본 authorization endpoint 규약
     * ({@code /oauth2/authorization/{registrationId}})을 그대로 따른다.
     * </p>
     */
    private String buildOAuth2AuthorizationUrl() {
        return "/oauth2/authorization/" + errorProperties.getOauth2LoginRegistrationId();
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
