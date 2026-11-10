package com.ids.keycloak.security.web.logout;

import java.io.IOException;
import java.util.Objects;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ids.keycloak.security.error.KeycloakErrorCode;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그아웃 주소에 POST가 아닌 요청이 오면 405 (LOGOUT-03). 링크·이미지 태그로 로그아웃시키는 것을 막고, 404 대신 이유를 알려 준다.
 * 사전 확인(OPTIONS)은 앞의 CORS가 응답한다.
 */
public class KeycloakLogoutMethodFilter extends OncePerRequestFilter {

    private final RequestMatcher logoutPath;
    private final KeycloakErrorResponseWriter errors;

    /**
     * @param logoutPath 로그아웃 주소 (메서드와 관계없이)
     */
    public KeycloakLogoutMethodFilter(RequestMatcher logoutPath, KeycloakErrorResponseWriter errors) {
        this.logoutPath = Objects.requireNonNull(logoutPath);
        this.errors = Objects.requireNonNull(errors);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        if (!"POST".equals(request.getMethod()) && logoutPath.matches(request)) {
            response.setHeader("Allow", "POST");
            errors.write(request, response, KeycloakErrorCode.METHOD_NOT_ALLOWED);
            return;
        }
        chain.doFilter(request, response);
    }
}
