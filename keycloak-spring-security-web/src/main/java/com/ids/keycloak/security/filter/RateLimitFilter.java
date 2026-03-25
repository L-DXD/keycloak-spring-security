package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakRateLimitProperties;
import com.ids.keycloak.security.config.RateLimitKeyStrategy;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 인증 시도에 대한 Rate Limiting을 수행하는 필터입니다.
 * <p>
 * 토큰 발급 API({@code /auth/token})와 Basic Auth 요청에 대해
 * 브루트포스 공격을 방지하기 위한 요청 제한을 적용합니다.
 * </p>
 * <p>
 * 필터 체인 순서: MdcRequestFilter → <b>RateLimitFilter</b> → BasicAuthenticationFilter → ...
 * </p>
 * <p>
 * Rate Limit 초과 시 429 Too Many Requests 응답을 반환하며,
 * {@code Retry-After} 헤더에 차단 해제까지 남은 시간(초)을 포함합니다.
 * </p>
 */
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String RATE_LIMIT_ERROR_BODY =
        "{\"error\":\"rate_limit_exceeded\",\"error_description\":\"Too many authentication attempts. Please try again later.\"}";

    private final RateLimiter rateLimiter;
    private final KeycloakRateLimitProperties properties;
    private final List<String> rateLimitPaths;

    public RateLimitFilter(RateLimiter rateLimiter,
                           KeycloakRateLimitProperties properties,
                           List<String> rateLimitPaths) {
        this.rateLimiter = rateLimiter;
        this.properties = properties;
        this.rateLimitPaths = rateLimitPaths;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Token API 경로 체크
        String requestUri = request.getRequestURI();
        for (String path : rateLimitPaths) {
            if (requestUri.equals(path)) {
                return false; // 필터링 대상
            }
        }

        // Basic Auth 포함 설정 시, Basic 헤더가 있는 요청도 대상
        if (properties.isIncludeBasicAuth()) {
            String authHeader = request.getHeader(AUTHORIZATION_HEADER);
            if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
                return false; // 필터링 대상
            }
        }

        return true; // 대상이 아니면 스킵
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientIp = getClientIp(request);
        String username = extractUsername(request);
        String authMethod = detectAuthMethod(request);

        RateLimitKeyStrategy strategy = properties.getKeyStrategy();
        boolean allowed = checkRateLimit(strategy, clientIp, username);

        if (!allowed) {
            String key = buildPrimaryKey(strategy, clientIp, username);
            long retryAfter = rateLimiter.getRetryAfterSeconds(key);

            AuthenticationEventLogger.logRateLimited(authMethod, clientIp, username);

            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(retryAfter));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(RATE_LIMIT_ERROR_BODY);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Rate Limit 키 전략에 따라 허용 여부를 판단합니다.
     * IP_AND_USERNAME 전략의 경우 두 기준 중 하나라도 초과하면 차단합니다.
     */
    private boolean checkRateLimit(RateLimitKeyStrategy strategy, String clientIp, String username) {
        switch (strategy) {
            case IP:
                return rateLimiter.tryAcquire("ip:" + clientIp);
            case USERNAME:
                if (username != null) {
                    return rateLimiter.tryAcquire("user:" + username);
                }
                // username 추출 불가 시 IP 기반 폴백
                return rateLimiter.tryAcquire("ip:" + clientIp);
            case IP_AND_USERNAME:
                boolean ipAllowed = rateLimiter.tryAcquire("ip:" + clientIp);
                if (!ipAllowed) {
                    return false;
                }
                if (username != null) {
                    return rateLimiter.tryAcquire("user:" + username);
                }
                return true;
            default:
                return rateLimiter.tryAcquire("ip:" + clientIp);
        }
    }

    /**
     * Retry-After 계산을 위한 기본 키를 반환합니다.
     */
    private String buildPrimaryKey(RateLimitKeyStrategy strategy, String clientIp, String username) {
        switch (strategy) {
            case USERNAME:
                return username != null ? "user:" + username : "ip:" + clientIp;
            case IP_AND_USERNAME:
            case IP:
            default:
                return "ip:" + clientIp;
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader(X_FORWARDED_FOR_HEADER);
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * 요청에서 username을 추출합니다.
     * Basic Auth 헤더에서 username을 디코딩하여 반환합니다.
     * Token API의 경우 body 파싱을 피하기 위해 null을 반환합니다.
     */
    private String extractUsername(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
            try {
                String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
                String credentials = new String(
                    Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
                int colonIndex = credentials.indexOf(':');
                if (colonIndex > 0) {
                    return credentials.substring(0, colonIndex);
                }
            } catch (IllegalArgumentException e) {
                // Base64 디코딩 실패 시 무시
            }
        }
        return null;
    }

    private String detectAuthMethod(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
            return "BASIC";
        }
        // Token API 경로 요청
        return "TOKEN_API";
    }
}
