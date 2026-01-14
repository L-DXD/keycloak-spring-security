package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

/**
 * 요청 시작 시 기본 메타데이터를 MDC에 주입하는 필터.
 * <p>
 * SecurityFilterChain 최상단에 위치하여 인증 실패 요청도 추적 가능하게 합니다.
 * <ul>
 *   <li>{@code traceId}: X-Request-Id 헤더 또는 자동 생성 UUID</li>
 *   <li>{@code httpMethod}: HTTP 메서드 (GET, POST 등)</li>
 *   <li>{@code requestUri}: 요청 경로</li>
 *   <li>{@code clientIp}: 클라이언트 IP 주소</li>
 * </ul>
 * <p>
 * 요청이 완료되면 finally 블록에서 MDC를 정리합니다.
 *
 * @author LeeBongSeung
 * @see MdcAuthenticationFilter
 */
public class MdcRequestFilter extends OncePerRequestFilter {

    private static final String X_REQUEST_ID_HEADER = "X-Request-Id";
    private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";

    private final LoggingContextAccessor contextAccessor;
    private final KeycloakSecurityProperties securityProperties;

    public MdcRequestFilter(LoggingContextAccessor contextAccessor, KeycloakSecurityProperties securityProperties) {
        this.contextAccessor = contextAccessor;
        this.securityProperties = securityProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            populateRequestContext(request);
            chain.doFilter(request, response);
        } finally {
            contextAccessor.clear();
        }
    }

    private void populateRequestContext(HttpServletRequest request) {
        KeycloakLoggingProperties loggingProps = securityProperties.getLogging();

        // traceId 설정
        if (loggingProps.isIncludeTraceId()) {
            String traceId = Optional.ofNullable(request.getHeader(X_REQUEST_ID_HEADER))
                    .filter(s -> !s.isBlank())
                    .orElseGet(() -> UUID.randomUUID().toString());
            contextAccessor.put(LoggingContextKeys.TRACE_ID, traceId);
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

        // 쿼리 스트링
        if (loggingProps.isIncludeQueryString()) {
            contextAccessor.put(LoggingContextKeys.QUERY_STRING, request.getQueryString());
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader(X_FORWARDED_FOR_HEADER);
        if (xff != null && !xff.isBlank()) {
            // X-Forwarded-For의 첫 번째 IP가 실제 클라이언트 IP
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
