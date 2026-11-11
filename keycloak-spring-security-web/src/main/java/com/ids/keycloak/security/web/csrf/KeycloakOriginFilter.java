package com.ids.keycloak.security.web.csrf;

import java.io.IOException;
import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ids.keycloak.security.error.KeycloakErrorCode;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Origin 확인 (V3-10, CSRF-05): 상태를 바꾸는 요청(GET·HEAD·OPTIONS·TRACE 말고)은 {@code Origin}이, 없으면 {@code Referer}의 origin이
 * 허용된 화면이어야 한다. 둘 다 없거나 다르면 403 {@code ORIGIN_NOT_ALLOWED}. CSRF 토큰 확인 앞에서 돈다.
 * <p>
 * 허용 origin은 CORS 설정({@link CorsConfigurationSource})을 그대로 따른다. CORS에 화면 origin을 더하면 여기도 같이 열린다.
 * 다른 화면의 Origin이 붙은 요청은 앞의 {@code CorsFilter}가 먼저 403으로 막고, 이 필터는 CORS가 보지 않는 요청(Origin 없음,
 * API 자신의 Origin)을 막는다. Keycloak이 서버에서 부르는 요청(back-channel 로그아웃)과 OIDC 콜백은 제외한다.
 */
public class KeycloakOriginFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakOriginFilter.class);
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private final CorsConfigurationSource cors;
    private final RequestMatcher excluded;
    private final KeycloakErrorResponseWriter errors;

    public KeycloakOriginFilter(CorsConfigurationSource cors, RequestMatcher excluded, KeycloakErrorResponseWriter errors) {
        this.cors = Objects.requireNonNull(cors);
        this.excluded = Objects.requireNonNull(excluded);
        this.errors = Objects.requireNonNull(errors);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        if (SAFE_METHODS.contains(request.getMethod()) || excluded.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        String origin = requestOrigin(request);
        if (origin == null || !isAllowedOrigin(request, origin)) {
            log.debug("[KSS] 허용되지 않은 출처의 {} {} 요청을 막았습니다 (origin={})", request.getMethod(), request.getRequestURI(), origin);
            errors.write(request, response, KeycloakErrorCode.ORIGIN_NOT_ALLOWED);
            return;
        }
        chain.doFilter(request, response);
    }

    /** 요청의 origin: {@code Origin} 헤더, 없으면 {@code Referer}의 {@code scheme://host[:port]}. 모르면 {@code null}. */
    protected String requestOrigin(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin != null && !origin.isBlank()) {
            return origin.trim();
        }
        String referer = request.getHeader("Referer");
        if (referer == null || referer.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(referer.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            String value = uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT);
            return uri.getPort() == -1 ? value : value + ":" + uri.getPort();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** CORS 설정이 이 origin을 허용하는가. {@code "null"}(샌드박스·파일)은 허용하지 않는다. */
    protected boolean isAllowedOrigin(HttpServletRequest request, String origin) {
        if ("null".equals(origin)) {
            return false;
        }
        CorsConfiguration configuration = cors.getCorsConfiguration(request);
        return configuration != null && origin.equals(configuration.checkOrigin(origin));
    }
}
