package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.util.ClientIpResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 요청 시작 시 기본 메타데이터를 MDC에 주입하는 필터.
 * <p>
 * SecurityFilterChain 최상단에 위치하여 인증 실패 요청도 추적 가능하게 합니다.
 * <ul>
 *   <li>{@code traceId}: X-Request-Id 헤더 또는 자동 생성 UUID (응답 헤더로도 회신)</li>
 *   <li>{@code httpMethod}: HTTP 메서드 (GET, POST 등)</li>
 *   <li>{@code requestUri}: 요청 경로</li>
 *   <li>{@code clientIp}: 클라이언트 IP 주소</li>
 *   <li>{@code queryString}: 쿼리 스트링 (URL 디코딩 + 길이 제한 + 마스킹)</li>
 *   <li>{@code userAgent}: User-Agent 헤더 (길이 제한 + 마스킹)</li>
 * </ul>
 * <p>
 * 민감정보 마스킹은 {@link LoggingValueSanitizer}에 위임합니다(기본 PII 마스킹, 사용자 교체 가능).
 * 요청이 완료되면 finally 블록에서 MDC를 정리합니다.
 *
 * @author LeeBongSeung
 * @see MdcAuthenticationFilter
 */
@Slf4j
public class MdcRequestFilter extends OncePerRequestFilter {

    private static final String X_REQUEST_ID_HEADER = "X-Request-Id";
    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final LoggingContextAccessor contextAccessor;
    private final KeycloakSecurityProperties securityProperties;
    private final LoggingValueSanitizer sanitizer;

    public MdcRequestFilter(LoggingContextAccessor contextAccessor,
                            KeycloakSecurityProperties securityProperties,
                            LoggingValueSanitizer sanitizer) {
        this.contextAccessor = contextAccessor;
        this.securityProperties = securityProperties;
        this.sanitizer = sanitizer;
    }

    /**
     * 로깅 제외 경로({@code keycloak.security.logging.exclude-patterns}, 기본 {@code /actuator/**})는
     * MDC 필터를 적용하지 않습니다. 헬스/메트릭 스크랩의 요청 로그 노이즈를 제거합니다.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        List<String> excludePatterns = securityProperties.getLogging().getExcludePatterns();
        if (excludePatterns == null || excludePatterns.isEmpty()) {
            return false;
        }
        String uri = request.getRequestURI();
        if (uri == null) {
            return false;
        }
        for (String pattern : excludePatterns) {
            if (PATH_MATCHER.match(pattern, uri)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        long startTime = System.currentTimeMillis();
        KeycloakLoggingProperties loggingProps = securityProperties.getLogging();
        try {
            populateRequestContext(request, response);
            chain.doFilter(request, response);
        } finally {
            // 응답 메트릭 (status, durationMs) + 종료 로그 — 기본 off (Tomcat AccessLog와 중복)
            if (loggingProps.isIncludeResponseMetrics()) {
                contextAccessor.put(LoggingContextKeys.STATUS, String.valueOf(response.getStatus()));
                contextAccessor.put(LoggingContextKeys.DURATION_MS,
                        String.valueOf(System.currentTimeMillis() - startTime));
                log.info("request completed");
            }
            contextAccessor.clear();
        }
    }

    private void populateRequestContext(HttpServletRequest request, HttpServletResponse response) {
        KeycloakLoggingProperties loggingProps = securityProperties.getLogging();

        // traceId 설정 (+ 응답 헤더 회신)
        if (loggingProps.isIncludeTraceId()) {
            String traceId = Optional.ofNullable(request.getHeader(X_REQUEST_ID_HEADER))
                    .filter(s -> !s.isBlank())
                    .orElseGet(() -> UUID.randomUUID().toString());
            contextAccessor.put(LoggingContextKeys.TRACE_ID, traceId);

            if (loggingProps.isReturnTraceIdHeader()) {
                response.setHeader(X_REQUEST_ID_HEADER, traceId);
            }
        }

        // 요청 메타데이터
        if (loggingProps.isIncludeHttpMethod()) {
            contextAccessor.put(LoggingContextKeys.HTTP_METHOD, request.getMethod());
        }
        if (loggingProps.isIncludeRequestUri()) {
            contextAccessor.put(LoggingContextKeys.REQUEST_URI, request.getRequestURI());
        }
        if (loggingProps.isIncludeClientIp()) {
            contextAccessor.put(LoggingContextKeys.CLIENT_IP, getClientIp(request));
        }

        // 쿼리 스트링: URL 디코딩 → 길이 제한 → 마스킹
        if (loggingProps.isIncludeQueryString()) {
            String query = request.getQueryString();
            if (query != null) {
                String sanitized = sanitizer.sanitize(
                        LoggingContextKeys.QUERY_STRING,
                        truncate(decode(query), loggingProps.getMaxQueryLength()));
                contextAccessor.put(LoggingContextKeys.QUERY_STRING, sanitized);
            }
        }

        // User-Agent: 길이 제한 → 마스킹
        if (loggingProps.isIncludeUserAgent()) {
            String userAgent = request.getHeader(USER_AGENT_HEADER);
            if (userAgent != null) {
                String sanitized = sanitizer.sanitize(
                        LoggingContextKeys.USER_AGENT,
                        truncate(userAgent, loggingProps.getMaxUserAgentLength()));
                contextAccessor.put(LoggingContextKeys.USER_AGENT, sanitized);
            }
        }
    }

    private String getClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(
            request.getHeader(X_FORWARDED_FOR_HEADER),
            request.getRemoteAddr(),
            securityProperties.getTrustedProxyCount()
        );
    }

    private String decode(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw;
        }
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return raw;
        }
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "...[truncated]";
    }
}
