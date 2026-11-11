package com.ids.keycloak.security.web.csrf;

import java.io.IOException;
import java.util.Objects;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * {@code GET /api/csrf} (V3-10, CSRF-01): 화면에 CSRF 토큰을 준다. 보안 체인 안 {@code CsrfFilter} 바로 뒤에서 응답하므로 로그인 여부와
 * 관계없이 받을 수 있다(로그인 전 토큰, CSRF-06).
 * <pre>
 * {"headerName":"X-XSRF-TOKEN","parameterName":"_csrf","token":"..."}
 * </pre>
 * 토큰은 Spring 기본(Xor) 처리기가 요청마다 다르게 가린 값이다. 어느 것을 보내도 통한다. 쿠키에 토큰이 없으면 새로 만들어 쿠키도 쓴다.
 */
public class KeycloakCsrfTokenEndpointFilter extends OncePerRequestFilter {

    private final String endpoint;

    /**
     * @param endpoint 토큰을 주는 경로 (context-path 뒤). 예: {@code /api/csrf}
     */
    public KeycloakCsrfTokenEndpointFilter(String endpoint) {
        this.endpoint = Objects.requireNonNull(endpoint);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (!"GET".equals(request.getMethod()) || !endpoint.equals(pathWithinApplication(request)) || token == null) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(body(token));
    }

    /** 응답 본문(JSON). */
    protected String body(CsrfToken token) {
        return "{\"headerName\":" + quote(token.getHeaderName()) + ",\"parameterName\":" + quote(token.getParameterName())
            + ",\"token\":" + quote(token.getToken()) + "}";
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return context != null && !context.isEmpty() && uri.startsWith(context) ? uri.substring(context.length()) : uri;
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c == '<') {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
