package com.ids.keycloak.security.web.logging;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ids.keycloak.security.config.KeycloakLoggingSettings;
import com.ids.keycloak.security.logging.ClientIpResolver;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 요청 처음에 요청 정보를 MDC에 넣고, 끝나면 넣은 키를 지운다. 보안 체인 맨 앞({@code SecurityContextHolderFilter} 앞)에 있어
 * 인증에 실패한 요청도 따라갈 수 있다. 키와 기본값은 v2와 같다.
 * <ul>
 *   <li>{@code traceId}: {@code X-Request-Id} 헤더 또는 새 UUID. 응답 {@code X-Request-Id}로 돌려준다.
 *       헤더 값이 영문·숫자·{@code . _ : -} 128자 안이 아니면 쓰지 않고 새로 만든다(로그 끼워 넣기 방지)</li>
 *   <li>{@code httpMethod}, {@code requestUri}, {@code clientIp}({@link ClientIpResolver})</li>
 *   <li>{@code queryString}(기본 끔): 디코딩 → 길이 제한 → {@link LoggingValueSanitizer}</li>
 *   <li>{@code userAgent}: 길이 제한 → {@link LoggingValueSanitizer}</li>
 *   <li>{@code status}, {@code durationMs}와 "request completed" 로그(기본 끔. 접근 로그와 겹친다)</li>
 * </ul>
 * {@code exclude-patterns}(기본 {@code /actuator/**})에 맞는 경로는 건너뛴다. 경로는 컨텍스트 경로를 뺀 앱 안 경로로 맞춘다.
 *
 * @see MdcAuthenticationFilter
 */
public class MdcRequestFilter extends OncePerRequestFilter {

    /** 요청 id 헤더. */
    public static final String REQUEST_ID_HEADER = "X-Request-Id";

    private static final Logger log = LoggerFactory.getLogger(MdcRequestFilter.class);
    private static final Pattern REQUEST_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final AntPathMatcher PATHS = new AntPathMatcher();

    private final LoggingContextAccessor context;
    private final KeycloakLoggingSettings settings;
    private final int trustedProxyCount;
    private final LoggingValueSanitizer sanitizer;

    public MdcRequestFilter(LoggingContextAccessor context, KeycloakLoggingSettings settings, int trustedProxyCount,
                            LoggingValueSanitizer sanitizer) {
        this.context = Objects.requireNonNull(context);
        this.settings = Objects.requireNonNull(settings);
        this.trustedProxyCount = trustedProxyCount;
        this.sanitizer = Objects.requireNonNull(sanitizer);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) {
            return false;
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        for (String pattern : settings.excludePatterns()) {
            if (PATHS.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        long start = System.nanoTime();
        try {
            putRequest(request, response);
            chain.doFilter(request, response);
        } finally {
            if (settings.includeResponseMetrics()) {
                context.put(LoggingContextKeys.STATUS, String.valueOf(response.getStatus()));
                context.put(LoggingContextKeys.DURATION_MS, String.valueOf((System.nanoTime() - start) / 1_000_000));
                log.info("request completed");
            }
            context.clear();
        }
    }

    /** 요청 정보를 MDC에 넣는다. 키를 더하려면 덮어쓰고 {@code super}를 부른다. */
    protected void putRequest(HttpServletRequest request, HttpServletResponse response) {
        if (settings.includeTraceId()) {
            String traceId = traceId(request.getHeader(REQUEST_ID_HEADER));
            context.put(LoggingContextKeys.TRACE_ID, traceId);
            if (settings.returnTraceIdHeader()) {
                response.setHeader(REQUEST_ID_HEADER, traceId);
            }
        }
        if (settings.includeHttpMethod()) {
            context.put(LoggingContextKeys.HTTP_METHOD, request.getMethod());
        }
        if (settings.includeRequestUri()) {
            context.put(LoggingContextKeys.REQUEST_URI, request.getRequestURI());
        }
        if (settings.includeClientIp()) {
            context.put(LoggingContextKeys.CLIENT_IP,
                ClientIpResolver.resolve(request.getHeader("X-Forwarded-For"), request.getRemoteAddr(), trustedProxyCount));
        }
        String query = request.getQueryString();
        if (settings.includeQueryString() && query != null) {
            context.put(LoggingContextKeys.QUERY_STRING,
                sanitizer.sanitize(LoggingContextKeys.QUERY_STRING, truncate(decode(query), settings.maxQueryLength())));
        }
        String userAgent = request.getHeader("User-Agent");
        if (settings.includeUserAgent() && userAgent != null) {
            context.put(LoggingContextKeys.USER_AGENT,
                sanitizer.sanitize(LoggingContextKeys.USER_AGENT, truncate(userAgent, settings.maxUserAgentLength())));
        }
    }

    /** 받은 요청 id가 쓸 만하면 그것, 아니면 새 UUID. */
    protected String traceId(String requested) {
        return requested != null && REQUEST_ID.matcher(requested).matches() ? requested : UUID.randomUUID().toString();
    }

    private static String decode(String raw) {
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return raw;
        }
    }

    private static String truncate(String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength) + "...[truncated]";
    }
}
