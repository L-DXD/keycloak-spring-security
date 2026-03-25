package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakRateLimitProperties;
import com.ids.keycloak.security.config.RateLimitKeyStrategy;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock
    private RateLimiter rateLimiter;

    @Mock
    private FilterChain filterChain;

    private KeycloakRateLimitProperties properties;
    private RateLimitFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        properties = new KeycloakRateLimitProperties();
        properties.setEnabled(true);
        properties.setMaxRequests(5);
        properties.setWindowSeconds(60);
        properties.setBlockDurationSeconds(300);
        properties.setKeyStrategy(RateLimitKeyStrategy.IP_AND_USERNAME);
        properties.setIncludeBasicAuth(true);

        filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Nested
    class 대상_경로_판별 {

        @Test
        void 토큰_발급_경로는_필터링_대상이다() throws Exception {
            request.setRequestURI("/auth/token");
            when(rateLimiter.tryAcquire(anyString())).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void Basic_Auth_헤더가_있으면_필터링_대상이다() throws Exception {
            request.setRequestURI("/api/data");
            String credentials = Base64.getEncoder()
                .encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.tryAcquire(anyString())).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void 비대상_경로는_통과한다() throws Exception {
            request.setRequestURI("/api/data");

            assertThat(filter.shouldNotFilter(request)).isTrue();
        }

        @Test
        void Bearer_토큰_요청은_대상이_아니다() throws Exception {
            request.setRequestURI("/api/data");
            request.addHeader("Authorization", "Bearer some-token");

            assertThat(filter.shouldNotFilter(request)).isTrue();
        }

        @Test
        void includeBasicAuth가_false면_Basic_Auth는_대상이_아니다() throws Exception {
            properties.setIncludeBasicAuth(false);
            filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));

            request.setRequestURI("/api/data");
            String credentials = Base64.getEncoder()
                .encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);

            assertThat(filter.shouldNotFilter(request)).isTrue();
        }
    }

    @Nested
    class Rate_Limit_차단 {

        @Test
        void 차단_시_429_응답을_반환한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(false);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
            verify(filterChain, never()).doFilter(request, response);
        }

        @Test
        void 차단_시_Retry_After_헤더를_포함한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(false);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getHeader("Retry-After")).isEqualTo("245");
        }

        @Test
        void 차단_시_JSON_에러_응답을_반환한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(false);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getContentType()).isEqualTo("application/json");
            assertThat(response.getContentAsString()).contains("rate_limit_exceeded");
        }

        @Test
        void 허용_시_다음_필터로_넘긴다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(200);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class IP_추출 {

        @Test
        void X_Forwarded_For_헤더가_있으면_첫번째_IP를_사용한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.addHeader("X-Forwarded-For", "10.0.0.5, 172.16.0.1, 192.168.1.1");
            request.setRemoteAddr("172.16.0.1");
            when(rateLimiter.tryAcquire("ip:10.0.0.5")).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void X_Forwarded_For가_없으면_remoteAddr를_사용한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.100");
            when(rateLimiter.tryAcquire("ip:192.168.1.100")).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class 키_전략별_동작 {

        @Test
        void IP_전략에서는_IP만으로_제한한다() throws Exception {
            properties.setKeyStrategy(RateLimitKeyStrategy.IP);
            filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));

            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void USERNAME_전략에서_Basic_Auth는_username으로_제한한다() throws Exception {
            properties.setKeyStrategy(RateLimitKeyStrategy.USERNAME);
            filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));

            request.setRequestURI("/api/data");
            request.setRemoteAddr("192.168.1.1");
            String credentials = Base64.getEncoder()
                .encodeToString("admin:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.tryAcquire("user:admin")).thenReturn(true);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void IP_AND_USERNAME_전략에서_IP와_username_모두_체크한다() throws Exception {
            properties.setKeyStrategy(RateLimitKeyStrategy.IP_AND_USERNAME);
            filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));

            request.setRequestURI("/api/data");
            request.setRemoteAddr("192.168.1.1");
            String credentials = Base64.getEncoder()
                .encodeToString("admin:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.tryAcquire("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.tryAcquire("user:admin")).thenReturn(false);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(100L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
        }
    }
}
