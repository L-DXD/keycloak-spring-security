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
 * 인증 실패 시에만 카운트하여, 정상 사용자가 피해를 받지 않도록 합니다.
 * 요청 전에는 차단 여부만 확인하고, 요청 후(post-filter) 인증 실패 응답(401, 403)이
 * 반환된 경우에만 실패를 기록합니다.
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

        // 1단계: 차단 여부만 확인 (카운트 증가 없음)
        if (isBlocked(strategy, clientIp, username)) {
            String key = buildPrimaryKey(strategy, clientIp, username);
            long retryAfter = rateLimiter.getRetryAfterSeconds(key);

            AuthenticationEventLogger.logRateLimited(authMethod, clientIp, username);

            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(retryAfter));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(RATE_LIMIT_ERROR_BODY);
            return;
        }

        // 2단계: 다음 필터 실행 (인증 처리)
        filterChain.doFilter(request, response);

        // 3단계: 인증 실패 응답(401, 403)인 경우에만 실패 기록
        int status = response.getStatus();
        if (status == 401 || status == 403) {
            recordFailure(strategy, clientIp, username);
        }
    }

    /**
     * Rate Limit 키 전략에 따라 차단 여부를 판단합니다.
     * IP_AND_USERNAME 전략의 경우 두 기준 중 하나라도 차단이면 차단합니다.
     */
    private boolean isBlocked(RateLimitKeyStrategy strategy, String clientIp, String username) {
        switch (strategy) {
            case IP:
                return rateLimiter.isBlocked("ip:" + clientIp);
            case USERNAME:
                if (username != null) {
                    return rateLimiter.isBlocked("user:" + username);
                }
                // username 추출 불가 시 IP 기반 폴백
                return rateLimiter.isBlocked("ip:" + clientIp);
            case IP_AND_USERNAME:
                if (rateLimiter.isBlocked("ip:" + clientIp)) {
                    return true;
                }
                if (username != null) {
                    return rateLimiter.isBlocked("user:" + username);
                }
                return false;
            default:
                return rateLimiter.isBlocked("ip:" + clientIp);
        }
    }

    /**
     * Rate Limit 키 전략에 따라 인증 실패를 기록합니다.
     */
    private void recordFailure(RateLimitKeyStrategy strategy, String clientIp, String username) {
        switch (strategy) {
            case IP:
                rateLimiter.recordFailure("ip:" + clientIp);
                break;
            case USERNAME:
                if (username != null) {
                    rateLimiter.recordFailure("user:" + username);
                } else {
                    rateLimiter.recordFailure("ip:" + clientIp);
                }
                break;
            case IP_AND_USERNAME:
                rateLimiter.recordFailure("ip:" + clientIp);
                if (username != null) {
                    rateLimiter.recordFailure("user:" + username);
                }
                break;
            default:
                rateLimiter.recordFailure("ip:" + clientIp);
                break;
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
