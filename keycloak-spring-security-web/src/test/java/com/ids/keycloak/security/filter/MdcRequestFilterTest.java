package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.NoOpLoggingValueSanitizer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT) // 불필요한 Stubbing 예외 방지 (헤더 조회 등)
class MdcRequestFilterTest {

    @Mock
    private LoggingContextAccessor contextAccessor;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private KeycloakSecurityProperties securityProperties;
    private KeycloakLoggingProperties loggingProperties;
    private MdcRequestFilter mdcRequestFilter;

    @BeforeEach
    void setUp() {
        securityProperties = new KeycloakSecurityProperties();
        loggingProperties = securityProperties.getLogging();
        // 기본 필터는 마스킹 비활성(NoOp)으로 두어 변환 로직(디코딩/truncate)만 격리 검증
        mdcRequestFilter = new MdcRequestFilter(contextAccessor, securityProperties, new NoOpLoggingValueSanitizer());
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 기본_설정일_때_필수_메타데이터가_MDC에_저장된다() throws ServletException, IOException {
            // Given
            when(request.getMethod()).thenReturn("GET");
            when(request.getRequestURI()).thenReturn("/api/test");
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");
            when(request.getHeader("X-Request-Id")).thenReturn("trace-123");

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(eq(LoggingContextKeys.TRACE_ID), anyString());
            verify(contextAccessor).put(LoggingContextKeys.HTTP_METHOD, "GET");
            verify(contextAccessor).put(LoggingContextKeys.REQUEST_URI, "/api/test");
            verify(contextAccessor).put(LoggingContextKeys.CLIENT_IP, "127.0.0.1");
            verify(filterChain).doFilter(request, response);
            verify(contextAccessor).clear();
        }

        @Test
        void 쿼리스트링_로깅이_활성화된_경우_MDC에_저장된다() throws ServletException, IOException {
            // Given
            loggingProperties.setIncludeQueryString(true);
            when(request.getQueryString()).thenReturn("param=value");
            when(request.getMethod()).thenReturn("GET"); // 기본 로깅 메서드 호출 방어

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(LoggingContextKeys.QUERY_STRING, "param=value");
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void 쿼리스트링_설정이_비활성화된_경우_저장되지_않는다() throws ServletException, IOException {
            // Given
            loggingProperties.setIncludeQueryString(false);
            when(request.getMethod()).thenReturn("GET"); // 기본 로깅 메서드 호출 방어

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor, never()).put(eq(LoggingContextKeys.QUERY_STRING), anyString());
        }

        @Test
        void 클라이언트_IP_설정이_비활성화된_경우_저장되지_않는다() throws ServletException, IOException {
            // Given
            loggingProperties.setIncludeClientIp(false);
            when(request.getMethod()).thenReturn("GET"); // 기본 로깅 메서드 호출 방어

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor, never()).put(eq(LoggingContextKeys.CLIENT_IP), anyString());
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 헤더에_X_Request_Id가_있으면_해당_값을_traceId로_사용한다() throws ServletException, IOException {
            // Given
            String existingTraceId = "existing-trace-id";
            when(request.getHeader("X-Request-Id")).thenReturn(existingTraceId);
            when(request.getMethod()).thenReturn("GET"); // 기본 로깅 메서드 호출 방어

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(LoggingContextKeys.TRACE_ID, existingTraceId);
        }

        @Test
        void X_Forwarded_For_헤더가_있으면_첫_번째_IP를_클라이언트_IP로_사용한다() throws ServletException, IOException {
            // Given
            String xff = "10.0.0.1, 10.0.0.2";
            when(request.getHeader("X-Forwarded-For")).thenReturn(xff);
            when(request.getMethod()).thenReturn("GET"); // 기본 로깅 메서드 호출 방어

            // When
            mdcRequestFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(LoggingContextKeys.CLIENT_IP, "10.0.0.1");
        }
    }

    @Nested
    @DisplayName("X-Request-Id 응답 회신")
    class TraceIdHeader {

        @Test
        @DisplayName("기본값(true)이면 응답 헤더에 traceId를 회신한다")
        void 응답_헤더에_회신() throws ServletException, IOException {
            when(request.getHeader("X-Request-Id")).thenReturn("trace-abc");
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(response).setHeader("X-Request-Id", "trace-abc");
        }

        @Test
        @DisplayName("returnTraceIdHeader=false이면 회신하지 않는다")
        void 회신_비활성화() throws ServletException, IOException {
            loggingProperties.setReturnTraceIdHeader(false);
            when(request.getHeader("X-Request-Id")).thenReturn("trace-abc");
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(response, never()).setHeader(eq("X-Request-Id"), anyString());
        }
    }

    @Nested
    @DisplayName("userAgent (R2)")
    class UserAgent {

        @Test
        @DisplayName("기본 활성화 시 User-Agent를 MDC에 저장한다")
        void userAgent_저장() throws ServletException, IOException {
            when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(contextAccessor).put(LoggingContextKeys.USER_AGENT, "Mozilla/5.0");
        }

        @Test
        @DisplayName("최대 길이(256)를 초과하면 truncate된다")
        void userAgent_truncate() throws ServletException, IOException {
            String longUa = "A".repeat(300);
            when(request.getHeader("User-Agent")).thenReturn(longUa);
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(contextAccessor).put(eq(LoggingContextKeys.USER_AGENT),
                argThat(v -> v.length() == 256 + "...[truncated]".length() && v.endsWith("...[truncated]")));
        }

        @Test
        @DisplayName("includeUserAgent=false이면 저장하지 않는다")
        void userAgent_비활성화() throws ServletException, IOException {
            loggingProperties.setIncludeUserAgent(false);
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(contextAccessor, never()).put(eq(LoggingContextKeys.USER_AGENT), anyString());
        }
    }

    @Nested
    @DisplayName("queryString 정제 (R3)")
    class QueryStringSanitize {

        @Test
        @DisplayName("URL 인코딩된 쿼리는 디코딩되어 저장된다")
        void query_디코딩() throws ServletException, IOException {
            loggingProperties.setIncludeQueryString(true);
            when(request.getQueryString()).thenReturn("name%3DJohn%20Doe");
            when(request.getMethod()).thenReturn("GET");

            mdcRequestFilter.doFilter(request, response, filterChain);

            verify(contextAccessor).put(LoggingContextKeys.QUERY_STRING, "name=John Doe");
        }

        @Test
        @DisplayName("PII 마스킹 sanitizer가 적용되면 쿼리의 이메일이 마스킹된다")
        void query_마스킹() throws ServletException, IOException {
            // 마스킹 sanitizer를 적용한 별도 필터
            MdcRequestFilter maskingFilter =
                new MdcRequestFilter(contextAccessor, securityProperties, new DefaultPiiMaskingSanitizer());
            loggingProperties.setIncludeQueryString(true);
            when(request.getQueryString()).thenReturn("email=alice@example.com");
            when(request.getMethod()).thenReturn("GET");

            maskingFilter.doFilter(request, response, filterChain);

            verify(contextAccessor).put(LoggingContextKeys.QUERY_STRING, "email=a***@example.com");
        }
    }
}
