
package com.ids.keycloak.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import com.ids.keycloak.security.util.SecurityHandlerUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * 인가(Authorization) 과정에서 실패하는 경우 호출되는 핸들러
 * KeycloakSecurityException 예외를 캐치하여 ErrorCode에 맞는 HTTP 응답을 생성
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final KeycloakErrorProperties errorProperties;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // KeycloakSecurityException이 원인인 경우, 해당 예외에서 errorCode를 추출
        if (accessDeniedException.getCause() instanceof KeycloakSecurityException cause) {
            log.debug("KeycloakAccessDeniedHandler: 인가 실패 - KeycloakSecurityException 발생 = {}, {}",
                cause.getErrorCode(), cause.getMessage());
        }

        // 페이지 이동 모드: true 시 브라우저 주소창을 실패 URL로 리다이렉트 (HTML 렌더링 환경)
        if (errorProperties.isRedirectEnabled()) {
            // AJAX 요청이고 ajaxReturnsJson이 true면 JSON 응답
            if (errorProperties.isAjaxReturnsJson() && SecurityHandlerUtil.isAjaxRequest(request)) {
                log.debug("KeycloakAccessDeniedHandler: AJAX 요청 - JSON 응답 반환");
                SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.ACCESS_DENIED);
                return;
            }

            String redirectUrl = errorProperties.getAccessDeniedRedirectUrl();
            log.debug("KeycloakAccessDeniedHandler: 인가 실패 - 리다이렉트 URL: {}", redirectUrl);
            response.sendRedirect(redirectUrl);
            return;
        }

        // API 모드: 기본 403 JSON 응답
        SecurityHandlerUtil.sendJsonResponse(response, objectMapper, ErrorCode.ACCESS_DENIED);
    }
}
