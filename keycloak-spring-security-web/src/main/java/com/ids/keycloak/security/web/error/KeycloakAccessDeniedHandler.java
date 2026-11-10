package com.ids.keycloak.security.web.error;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.ids.keycloak.security.error.KeycloakErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** 권한이 없을 때 403 JSON. */
public class KeycloakAccessDeniedHandler implements AccessDeniedHandler {

    private final KeycloakErrorResponseWriter writer;

    public KeycloakAccessDeniedHandler(KeycloakErrorResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
        throws IOException {
        writer.write(request, response, KeycloakErrorCode.ACCESS_DENIED);
    }
}
