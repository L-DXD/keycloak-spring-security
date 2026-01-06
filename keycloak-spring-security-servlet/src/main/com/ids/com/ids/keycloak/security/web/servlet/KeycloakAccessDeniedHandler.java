
package com.ids.keycloak.security.web.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 인가(Authorization) 과정에서 실패하는 경우 호출되는 핸들러
 * KeycloakSecurityException 예외를 캐치하여 ErrorCode에 맞는 HTTP 응답을 생성
 */
@RequiredArgsConstructor
public class KeycloakAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // KeycloakSecurityException이 원인인 경우, 해당 예외에서 errorCode를 추출
        if (accessDeniedException.getCause() instanceof KeycloakSecurityException) {
            KeycloakSecurityException ex = (KeycloakSecurityException) accessDeniedException.getCause();
            ErrorCode errorCode = ex.getErrorCode();
            response.setStatus(errorCode.getHttpStatus());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try (OutputStream os = response.getOutputStream()) {
                objectMapper.writeValue(os, new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage()));
                os.flush();
            }
        } else {
            // 그 외 인가 예외는 기본 403 응답
            ErrorCode defaultError = ErrorCode.ACCESS_DENIED;
            response.setStatus(defaultError.getHttpStatus());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try (OutputStream os = response.getOutputStream()) {
                objectMapper.writeValue(os, new ErrorResponse(defaultError.getCode(), accessDeniedException.getMessage()));
                os.flush();
            }
        }
    }

    /**
     * JSON 에러 응답을 위한 내부 레코드
     */
    private record ErrorResponse(String code, String message) {
    }
}
