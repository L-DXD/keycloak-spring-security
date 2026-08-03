
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

    /** OAuth2 로그인 authorize 엔드포인트 경로 prefix (C-B 자기참조 가드). */
    private static final String OAUTH2_AUTHORIZATION_PREFIX = "/oauth2/authorization/";
    /** OAuth2 로그인 콜백(redirect_uri) 경로 prefix (C-B 자기참조 가드). */
    private static final String OAUTH2_CALLBACK_PREFIX = "/login/oauth2/code/";

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
        // basicAuthEnabled=false로 꺼져 있어도 마찬가지)과 Accept: text/html을 명시적으로 수용하는
        // (즉 브라우저의 HTML 네비게이션으로 보이는, H-B) 요청만 기본적으로 authorization endpoint로
        // 리다이렉트해 기존 SSO 로그인 플로우를 그대로 유지한다. Authorization 헤더 보유 자체가
        // "프로그래밍적 클라이언트"의 근거이므로 basicAuthEnabled 토글과 무관하게 리다이렉트 대상에서
        // 제외한다. oauth2LoginRedirectEnabled=false로 끄면 항상 401 JSON을 반환한다(순수 API 서버).
        // H-B: 판정 기준은 SecurityHandlerUtil#isAjaxRequest("AJAX가 아니면 브라우저")가 아니라
        // SecurityHandlerUtil#acceptsHtmlExplicitly("Accept: text/html을 실제로 명시했을 때만
        // 브라우저")다 — Accept 헤더가 없거나 */* 단독인 curl·서버간 호출·일부 모바일 클라이언트가
        // 리다이렉트(302) 대신 401 JSON을 받도록 하기 위함이다(2.0.2 대비 breaking 회귀 수정).
        // C-B: 실패한 요청 자체가 OAuth2 authorization/callback 경로면 리다이렉트하지 않는다
        // (자기참조 가드 — 무한 루프 방지).
        if (errorProperties.isOauth2LoginRedirectEnabled()
            && !isBasicAuthRequest(request)
            && !isOAuth2FlowPath(request)
            && SecurityHandlerUtil.acceptsHtmlExplicitly(request)) {
            String authorizationUrl = buildOAuth2AuthorizationUrl(request);
            log.debug("KeycloakAuthenticationEntryPoint: 인증 실패 - OAuth2 로그인으로 리다이렉트: {}", authorizationUrl);
            response.sendRedirect(authorizationUrl);
            return;
        }

        // API 모드: 기본 401 JSON 응답
        SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.AUTHENTICATION_FAILED);
    }

    /**
     * OAuth2 로그인 authorization endpoint URL을 생성합니다 (C-1, H-A).
     * <p>
     * Spring Security {@code oauth2Login}의 기본 authorization endpoint 규약
     * ({@code /oauth2/authorization/{registrationId}})을 그대로 따른다.
     * </p>
     * <p>
     * <b>H-A (context-path 배포 404):</b> {@link HttpServletResponse#sendRedirect(String)}에
     * {@code /}로 시작하는 경로를 넘기면 컨테이너 루트(서버 도메인) 기준으로 해석된다.
     * {@code /myapp} 같은 context-path로 배포된 애플리케이션에서 context-path를 붙이지 않으면
     * 실제로는 {@code /myapp/oauth2/authorization/keycloak}이어야 할 경로가
     * {@code /oauth2/authorization/keycloak}으로 리다이렉트되어 404가 된다. Spring Security의
     * {@code LoginUrlAuthenticationEntryPoint}와 동일하게 {@link HttpServletRequest#getContextPath()}를
     * prefix로 붙인다(context-path가 없는 환경에서는 빈 문자열이므로 회귀가 없다).
     * </p>
     */
    private String buildOAuth2AuthorizationUrl(HttpServletRequest request) {
        return request.getContextPath() + OAUTH2_AUTHORIZATION_PREFIX
            + errorProperties.getOauth2LoginRegistrationId();
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

    /**
     * 실패한 요청 자체가 OAuth2 authorization/callback 경로인지 확인합니다 (C-B 자기참조 가드).
     * <p>
     * 정상 구성이라면 이 경로들은 Spring Security의 OAuth2 관련 필터가 이 EntryPoint보다 먼저
     * 처리하지만, 예외적인 구성(예: 필터 순서 커스터마이즈)에서 이 경로 자체가 미인증으로
     * EntryPoint까지 도달하면, 여기서 다시 같은 authorization endpoint로 리다이렉트해 무한 루프가
     * 될 수 있다. 이를 방지하기 위해 이 경로들은 리다이렉트 대상에서 제외하고 401 JSON으로 처리한다.
     * </p>
     */
    private boolean isOAuth2FlowPath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri == null || requestUri.isEmpty()) {
            return false;
        }
        String contextPath = request.getContextPath();
        String path = requestUri;
        if (contextPath != null && !contextPath.isEmpty() && requestUri.startsWith(contextPath)) {
            path = requestUri.substring(contextPath.length());
        }
        return path.startsWith(OAUTH2_AUTHORIZATION_PREFIX) || path.startsWith(OAUTH2_CALLBACK_PREFIX);
    }
}
