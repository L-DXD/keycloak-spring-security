
package com.ids.keycloak.security.web.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 인증(Authentication) 과정에서 실패하는 경우 호출되는 핸들러
 * KeycloakSecurityException 예외를 캐치하여 ErrorCode에 맞는 HTTP 응답을 생성
 */
@RequiredArgsConstructor
public class KeycloakAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // KeycloakSecurityException이 원인인 경우, 해당 예외에서 errorCode를 추출
        if (authException.getCause() instanceof KeycloakSecurityException) {
            KeycloakSecurityException ex = (KeycloakSecurityException) authException.getCause();
            ErrorCode errorCode = ex.getErrorCode();
            response.setStatus(errorCode.getHttpStatus());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try (OutputStream os = response.getOutputStream()) {
                objectMapper.writeValue(os, new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage()));
                os.flush();
            }
        } else {
            // 그 외 인증 예외는 기본 401 응답
            ErrorCode defaultError = ErrorCode.AUTHENTICATION_FAILED;
            response.setStatus(defaultError.getHttpStatus());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try (OutputStream os = response.getOutputStream()) {
                objectMapper.writeValue(os, new ErrorResponse(defaultError.getCode(), authException.getMessage()));
                os.flush();
            }
        }
    }
}
