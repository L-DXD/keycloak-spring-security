package com.ids.keycloak.security.web.error;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.ids.keycloak.security.error.KeycloakErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그인이 필요할 때 401 JSON을 준다 (LOGIN-01). 화면(SPA)이 {@code loginUrl}로 이동시킨다. 로그인 화면으로 302하지 않는다.
 */
public class KeycloakAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final KeycloakErrorResponseWriter writer;

    public KeycloakAuthenticationEntryPoint(KeycloakErrorResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
        throws IOException {
        writer.write(request, response, KeycloakErrorCode.AUTHENTICATION_REQUIRED);
    }
}
