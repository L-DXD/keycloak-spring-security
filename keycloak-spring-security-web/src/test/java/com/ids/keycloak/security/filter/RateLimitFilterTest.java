package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
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
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        void Basic_Auth_헤더가_있으면_필터링_대상이다() throws Exception {
            request.setRequestURI("/api/data");
            String credentials = Base64.getEncoder()
                .encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

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
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
            verify(filterChain, never()).doFilter(request, response);
        }

        @Test
        void 차단_시_Retry_After_헤더를_포함한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getHeader("Retry-After")).isEqualTo("245");
        }

        @Test
        void 차단_시_JSON_에러_응답을_반환한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getContentType()).isEqualTo("application/json");
            assertThat(response.getContentAsString()).contains("rate_limit_exceeded");
        }

        @Test
        void 허용_시_다음_필터로_넘긴다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(200);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    class 인증_실패시만_카운트 {

        @Test
        void 인증_성공시_실패를_기록하지_않는다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            // filterChain에서 200 응답 (기본값)
            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(200);
            verify(rateLimiter, never()).recordFailure(anyString());
        }

        @Test
        void 인증_실패_401시_실패를_기록한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            // filterChain에서 401 응답 설정
            doAnswer(invocation -> {
                response.setStatus(401);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void 인증_실패_403시_실패를_기록한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            // filterChain에서 403 응답 설정
            doAnswer(invocation -> {
                response.setStatus(403);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void TOKEN_API_요청에서_400_invalid_grant_응답시_실패를_기록한다() throws Exception {
            // Keycloak 토큰 엔드포인트는 invalid_grant(잘못된 자격증명)를 OAuth2 표준에 따라
            // 400으로 응답한다. 이를 기록하지 않으면 /auth/token 브루트포스가 Rate Limit을
            // 완전히 우회한다(Advisory 2 리뷰 신규 로직).
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            doAnswer(invocation -> {
                response.setStatus(400);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void trustedProxyCount가_1인_상태에서_TOKEN_API_400_응답시_ClientIpResolver로_해석된_IP로_실패를_기록한다()
            throws Exception {
            // 공격자가 통제 가능한 XFF 첫 값("10.0.0.5")이 아니라, 신뢰 프록시가 append한
            // "172.16.0.1"(ClientIpResolver가 해석한 IP)로 실패가 기록되어야 한다.
            filter.setTrustedProxyCount(1);
            request.setRequestURI("/auth/token");
            request.addHeader("X-Forwarded-For", "10.0.0.5, 172.16.0.1");
            request.setRemoteAddr("172.16.0.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            doAnswer(invocation -> {
                response.setStatus(400);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter).recordFailure("ip:172.16.0.1");
            verify(rateLimiter, never()).recordFailure("ip:10.0.0.5");
        }

        @Test
        void Basic_Auth_요청에서_400_응답은_실패로_기록하지_않는다() throws Exception {
            // Basic Auth 경로의 400은 TOKEN_API 전용 예외 규칙 대상이 아니므로,
            // 과다 카운트(false positive)를 방지하기 위해 기록되지 않아야 한다.
            request.setRequestURI("/api/data");
            request.setRemoteAddr("192.168.1.1");
            String credentials = Base64.getEncoder()
                .encodeToString("admin:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            doAnswer(invocation -> {
                response.setStatus(400);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter, never()).recordFailure(anyString());
        }

        @Test
        void IP_AND_USERNAME_전략에서_실패시_두_키_모두_기록한다() throws Exception {
            properties.setKeyStrategy(RateLimitKeyStrategy.IP_AND_USERNAME);
            filter = new RateLimitFilter(rateLimiter, properties, List.of("/auth/token"));

            request.setRequestURI("/api/data");
            request.setRemoteAddr("192.168.1.1");
            String credentials = Base64.getEncoder()
                .encodeToString("admin:pass".getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + credentials);
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            doAnswer(invocation -> {
                response.setStatus(401);
                return null;
            }).when(filterChain).doFilter(request, response);

            filter.doFilterInternal(request, response, filterChain);

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
            verify(rateLimiter).recordFailure("user:admin");
        }
    }

    @Nested
    class IP_추출 {

        @Test
        void trustedProxyCount_기본값_0에서는_스푸핑된_X_Forwarded_For를_무시하고_remoteAddr를_사용한다() throws Exception {
            // 보안 기본값(trustedProxyCount=0): 클라이언트가 조작 가능한 XFF는 완전히 무시한다.
            request.setRequestURI("/auth/token");
            request.addHeader("X-Forwarded-For", "10.0.0.5, 172.16.0.1, 192.168.1.1");
            request.setRemoteAddr("172.16.0.1");
            when(rateLimiter.isBlocked("ip:172.16.0.1")).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(rateLimiter, never()).isBlocked("ip:10.0.0.5");
        }

        @Test
        void trustedProxyCount가_1이면_신뢰_프록시가_append한_값_바로_앞을_클라이언트_IP로_사용한다() throws Exception {
            // X-Forwarded-For: client, proxy1 (append 방식) 에서 신뢰 프록시 1개(proxy1)가 append한
            // 우측 항목의 바로 앞("172.16.0.1", 마지막 신뢰 프록시가 관찰한 IP)을 클라이언트 IP로 사용.
            // "10.0.0.5"는 공격자가 통제 가능한 좌측 구간이므로 신뢰해서는 안 된다.
            filter.setTrustedProxyCount(1);
            request.setRequestURI("/auth/token");
            request.addHeader("X-Forwarded-For", "10.0.0.5, 172.16.0.1");
            request.setRemoteAddr("172.16.0.1");
            when(rateLimiter.isBlocked("ip:172.16.0.1")).thenReturn(false);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(rateLimiter, never()).isBlocked("ip:10.0.0.5");
        }

        @Test
        void X_Forwarded_For가_없으면_remoteAddr를_사용한다() throws Exception {
            request.setRequestURI("/auth/token");
            request.setRemoteAddr("192.168.1.100");
            when(rateLimiter.isBlocked("ip:192.168.1.100")).thenReturn(false);

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
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(false);

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
            when(rateLimiter.isBlocked("user:admin")).thenReturn(false);

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
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(false);
            when(rateLimiter.isBlocked("user:admin")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(100L);

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
        }
    }
}
