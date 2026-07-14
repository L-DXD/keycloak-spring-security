package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakRateLimitProperties;
import com.ids.keycloak.security.config.RateLimitKeyStrategy;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@link ReactiveRateLimitFilter} 단위 테스트.
 *
 * <p>servlet 모듈의 {@code RateLimitFilter}와 동일한 계약(429/Retry-After, 401·403·
 * (TOKEN_API 한정) 400 실패 기록, IP_AND_USERNAME 전략, {@code ClientIpResolver} 기반
 * IP 추출)을 WebFlux 스택에서도 검증한다. Advisory 2 리뷰(off-by-one XFF 수정, 400
 * invalid_grant 캡처) 이전에는 이 필터에 대한 전용 테스트가 존재하지 않았다.</p>
 */
@ExtendWith(MockitoExtension.class)
class ReactiveRateLimitFilterTest {

    @Mock
    private RateLimiter rateLimiter;

    private KeycloakRateLimitProperties properties;
    private ReactiveRateLimitFilter filter;

    private static final String TOKEN_PATH = "/auth/token";

    @BeforeEach
    void setUp() {
        properties = new KeycloakRateLimitProperties();
        properties.setEnabled(true);
        properties.setMaxRequests(5);
        properties.setWindowSeconds(60);
        properties.setBlockDurationSeconds(300);
        properties.setKeyStrategy(RateLimitKeyStrategy.IP_AND_USERNAME);
        properties.setIncludeBasicAuth(true);

        filter = new ReactiveRateLimitFilter(rateLimiter, properties, List.of(TOKEN_PATH));
    }

    private MockServerWebExchange exchange(String path, String remoteAddr) {
        MockServerHttpRequest request = MockServerHttpRequest.get(path)
            .remoteAddress(new InetSocketAddress(remoteAddr, 12345))
            .build();
        return MockServerWebExchange.from(request);
    }

    private MockServerWebExchange exchangeWithXff(String path, String remoteAddr, String xff) {
        MockServerHttpRequest request = MockServerHttpRequest.get(path)
            .remoteAddress(new InetSocketAddress(remoteAddr, 12345))
            .header("X-Forwarded-For", xff)
            .build();
        return MockServerWebExchange.from(request);
    }

    private MockServerWebExchange exchangeWithBasicAuth(String path, String remoteAddr,
        String username, String password) {
        String credentials = Base64.getEncoder()
            .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        MockServerHttpRequest request = MockServerHttpRequest.get(path)
            .remoteAddress(new InetSocketAddress(remoteAddr, 12345))
            .header(HttpHeaders.AUTHORIZATION, "Basic " + credentials)
            .build();
        return MockServerWebExchange.from(request);
    }

    private WebFilterChain chainReturningStatus(HttpStatus status) {
        return ex -> {
            ex.getResponse().setStatusCode(status);
            return Mono.empty();
        };
    }

    @Nested
    class 대상_경로가_아니면_통과 {

        @Test
        void 토큰_경로가_아니고_Basic_헤더도_없으면_필터를_건너뛴다() {
            MockServerWebExchange ex = exchange("/api/data", "192.168.1.1");
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
            verify(rateLimiter, never()).isBlocked(anyString());
        }

        @Test
        void includeBasicAuth가_false면_Basic_Auth_요청도_건너뛴다() {
            properties.setIncludeBasicAuth(false);
            filter = new ReactiveRateLimitFilter(rateLimiter, properties, List.of(TOKEN_PATH));

            MockServerWebExchange ex = exchangeWithBasicAuth("/api/data", "192.168.1.1", "admin", "pass");
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
            verify(rateLimiter, never()).isBlocked(anyString());
        }
    }

    @Nested
    class Rate_Limit_차단 {

        @Test
        void 차단_시_429와_Retry_After_헤더를_반환한다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(245L);
            WebFilterChain chain = e -> Mono.error(new AssertionError("차단 시 다음 필터가 호출되면 안 된다"));

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
            assertThat(ex.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("245");
        }

        @Test
        void 차단_시_JSON_에러_바디를_반환한다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(true);
            when(rateLimiter.getRetryAfterSeconds("ip:192.168.1.1")).thenReturn(10L);
            WebFilterChain chain = e -> Mono.empty();

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            StepVerifier.create(ex.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).contains("rate_limit_exceeded"))
                .verifyComplete();
        }

        @Test
        void 허용_시_다음_필터로_넘긴다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked("ip:192.168.1.1")).thenReturn(false);
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
        }
    }

    @Nested
    class TOKEN_API_400_실패_기록_신규_로직 {

        @Test
        void TOKEN_API_요청에서_400_invalid_grant_응답시_실패를_기록한다() {
            // Keycloak 토큰 엔드포인트는 invalid_grant를 OAuth2 표준에 따라 400으로 응답한다.
            // 이를 기록하지 않으면 /auth/token 브루트포스가 Rate Limit을 완전히 우회한다.
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.BAD_REQUEST)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void trustedProxyCount가_1인_상태에서_TOKEN_API_400_응답시_ClientIpResolver로_해석된_IP로_실패를_기록한다() {
            // 신뢰 프록시(trusted-proxy-count>0) + 400 캡처 조합. 공격자가 통제 가능한 XFF
            // 첫 값("10.0.0.5")이 아니라, 신뢰 프록시가 append한 "172.16.0.1"로 기록되어야 한다.
            filter.setTrustedProxyCount(1);
            MockServerWebExchange ex = exchangeWithXff(TOKEN_PATH, "172.16.0.1", "10.0.0.5, 172.16.0.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.BAD_REQUEST)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:172.16.0.1");
            verify(rateLimiter, never()).recordFailure("ip:10.0.0.5");
        }

        @Test
        void TOKEN_API_요청에서_401_응답시_실패를_기록한다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.UNAUTHORIZED)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void TOKEN_API_요청에서_403_응답시_실패를_기록한다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.FORBIDDEN)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }

        @Test
        void TOKEN_API_요청에서_200_응답시_실패를_기록하지_않는다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.1");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.OK)))
                .verifyComplete();

            verify(rateLimiter, never()).recordFailure(anyString());
        }
    }

    @Nested
    class Basic_Auth_400은_과다카운트_방지로_기록되지_않음 {

        @Test
        void Basic_Auth_요청에서_400_응답은_실패로_기록하지_않는다() {
            MockServerWebExchange ex = exchangeWithBasicAuth("/api/data", "192.168.1.1", "admin", "pass");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.BAD_REQUEST)))
                .verifyComplete();

            verify(rateLimiter, never()).recordFailure(anyString());
        }

        @Test
        void Basic_Auth_요청에서_401_응답은_실패로_기록한다() {
            MockServerWebExchange ex = exchangeWithBasicAuth("/api/data", "192.168.1.1", "admin", "pass");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.UNAUTHORIZED)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
        }
    }

    @Nested
    class IP_추출_ClientIpResolver_위임 {

        @Test
        void trustedProxyCount_기본값_0에서는_스푸핑된_XFF를_무시하고_remoteAddress를_사용한다() {
            MockServerWebExchange ex = exchangeWithXff(TOKEN_PATH, "172.16.0.1", "10.0.0.5, 172.16.0.1, 192.168.1.1");
            when(rateLimiter.isBlocked("ip:172.16.0.1")).thenReturn(false);
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
            verify(rateLimiter, never()).isBlocked("ip:10.0.0.5");
        }

        @Test
        void XFF_헤더가_없으면_remoteAddress를_사용한다() {
            MockServerWebExchange ex = exchange(TOKEN_PATH, "192.168.1.100");
            when(rateLimiter.isBlocked("ip:192.168.1.100")).thenReturn(false);
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
        }
    }

    /**
     * keycloak-spring-security-web의 {@code RateLimitFilterTest}와 동일한 입력값에 대해
     * 동일한 rate limit 키 문자열을 산출해야 함(servlet/webflux 동등성)을 검증한다.
     */
    @Nested
    class Servlet_대응_동등성_검증 {

        @Test
        void IP_AND_USERNAME_전략에서_실패시_두_키_모두_기록한다_servlet과_동일_키_포맷() {
            // RateLimitFilterTest#IP_AND_USERNAME_전략에서_실패시_두_키_모두_기록한다 와 동일한
            // 입력(IP=192.168.1.1, username=admin)에 대해 동일한 "ip:"/"user:" 키 포맷을 사용해야 한다.
            MockServerWebExchange ex = exchangeWithBasicAuth("/api/data", "192.168.1.1", "admin", "pass");
            when(rateLimiter.isBlocked(anyString())).thenReturn(false);

            StepVerifier.create(filter.filter(ex, chainReturningStatus(HttpStatus.UNAUTHORIZED)))
                .verifyComplete();

            verify(rateLimiter).recordFailure("ip:192.168.1.1");
            verify(rateLimiter).recordFailure("user:admin");
        }

        @Test
        void trustedProxyCount가_1이면_신뢰_프록시가_append한_값_바로_앞을_클라이언트_IP로_사용한다_servlet과_동일() {
            // RateLimitFilterTest#trustedProxyCount가_1이면_신뢰_프록시가_append한_값_바로_앞을_클라이언트_IP로_사용한다
            // 와 동일한 입력(XFF="10.0.0.5, 172.16.0.1", trustedProxyCount=1)에 대해 동일한 결과를 산출해야 한다.
            filter.setTrustedProxyCount(1);
            MockServerWebExchange ex = exchangeWithXff(TOKEN_PATH, "172.16.0.1", "10.0.0.5, 172.16.0.1");
            when(rateLimiter.isBlocked("ip:172.16.0.1")).thenReturn(false);
            boolean[] chainCalled = {false};
            WebFilterChain chain = e -> {
                chainCalled[0] = true;
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

            assertThat(chainCalled[0]).isTrue();
            verify(rateLimiter, never()).isBlocked("ip:10.0.0.5");
        }
    }
}
