package com.ids.keycloak.security.web.error;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;

import com.ids.keycloak.security.error.KeycloakErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** 권한이 없을 때 403 JSON. CSRF 토큰 실패면 코드 {@code INVALID_CSRF_TOKEN}(화면이 토큰을 다시 받게). */
public class KeycloakAccessDeniedHandler implements AccessDeniedHandler {

    private final KeycloakErrorResponseWriter writer;

    public KeycloakAccessDeniedHandler(KeycloakErrorResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
        throws IOException {
        writer.write(request, response, accessDeniedException instanceof CsrfException
            ? KeycloakErrorCode.INVALID_CSRF_TOKEN : KeycloakErrorCode.ACCESS_DENIED);
    }
}
