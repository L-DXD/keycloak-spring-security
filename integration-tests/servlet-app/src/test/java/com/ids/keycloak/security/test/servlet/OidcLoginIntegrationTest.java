package com.ids.keycloak.security.test.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ids.keycloak.security.authentication.AuthenticationMethodDetector;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.filter.KeycloakAuthenticationFilter;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Phase 4-4 통합 테스트 — KeycloakAuthenticationFilter 핵심 시나리오.
 * Spring 컨텍스트 없이 필터 레벨에서 AC#1~AC#4를 통합 검증합니다.
 *
 * <p>검증 항목:
 * <ol>
 *   <li>AC#1: POST /api/keycloak/login → ERROR 로그 0건</li>
 *   <li>AC#2: POST /api/keycloak/login → result=FAILURE 오탐 0건</li>
 *   <li>AC#3: 4개 경로(Bearer/Basic/CREDENTIAL_LOGIN/OIDC_COOKIE) 회귀 없음</li>
 *   <li>AC#4: 세션 없음 이벤트로 rate-limiter 카운터 미증가 (logNoSession은 FAILURE 미기록)</li>
 * </ol>
 * </p>
 */
class OidcLoginIntegrationTest {

    private KeycloakAuthenticationFilter filter;
    private AuthenticationManager authenticationManager;
    private KeycloakSessionManager sessionManager;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() throws Exception {
        authenticationManager = mock(AuthenticationManager.class);
        KeycloakAuthenticationProvider authProvider = mock(KeycloakAuthenticationProvider.class);
        sessionManager = mock(KeycloakSessionManager.class);
        KeycloakClient keycloakClient = mock(KeycloakClient.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

        filter = new KeycloakAuthenticationFilter(
            authenticationManager,
            authProvider,
            sessionManager,
            keycloakClient,
            List.of("/api/keycloak/token", "/api/keycloak/refresh", "/api/keycloak/logout"),
            List.of("/api/keycloak/login")
        );

        filterChain = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // =========================================================
    // AC#1 + AC#2: POST /api/keycloak/login 시나리오
    // =========================================================

    @Nested
    @DisplayName("AC#1,2: POST /api/keycloak/login — ERROR/FAILURE 오탐 없음")
    class CredentialLoginScenario {

        @Test
        @DisplayName("POST /api/keycloak/login 요청에서 ERROR 로그가 0건이어야 한다 (AC#1)")
        void postLoginRequest_shouldProduceZeroErrorLogs() throws Exception {
            // Given
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(filterLogger, eventLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            // Authorization 헤더 없음 — body 기반 로그인 시뮬레이션
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then — AC#1: ERROR 레벨 로그 0건
                long errorCount = appender.list.stream()
                    .filter(e -> e.getLevel() == Level.ERROR)
                    .count();
                assertThat(errorCount)
                    .as("POST /api/keycloak/login 시 ERROR 로그가 발생하면 안 된다 (AC#1)")
                    .isZero();
            } finally {
                detachAppender(appender, filterLogger, eventLogger);
            }
        }

        @Test
        @DisplayName("POST /api/keycloak/login 요청에서 result=FAILURE 감사 로그가 0건이어야 한다 (AC#2)")
        void postLoginRequest_shouldProduceZeroFailureAuditLogs() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(eventLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then — AC#2: result=FAILURE 오탐 0건
                boolean hasFailureLog = appender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=FAILURE"));
                assertThat(hasFailureLog)
                    .as("[AUTH] result=FAILURE method=OIDC_COOKIE 오탐이 발생하면 안 된다 (AC#2)")
                    .isFalse();
            } finally {
                detachAppender(appender, eventLogger);
            }
        }

        @Test
        @DisplayName("POST /api/keycloak/login 요청은 필터 체인이 정상 진행되어야 한다")
        void postLoginRequest_shouldProceedThroughFilterChain() throws Exception {
            // Given
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            // When
            filter.doFilter(request, response, chain);

            // Then — 필터 체인이 실행되었음 (chain.getRequest() != null 로 확인)
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        @DisplayName("POST /api/keycloak/login 요청에서 result=SKIPPED 감사 로그가 기록된다")
        void postLoginRequest_shouldLogSkipped() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(eventLogger, Level.INFO);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then
                boolean hasSkippedLog = appender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=SKIPPED"));
                assertThat(hasSkippedLog)
                    .as("CREDENTIAL_LOGIN 경로는 result=SKIPPED로 감사 기록되어야 한다")
                    .isTrue();
            } finally {
                detachAppender(appender, eventLogger);
            }
        }
    }

    // =========================================================
    // AC#3: 4개 경로 회귀 시나리오
    // =========================================================

    @Nested
    @DisplayName("AC#3: 4개 경로 회귀 — Bearer/Basic/CREDENTIAL_LOGIN/OIDC_COOKIE")
    class FourPathRegressionScenario {

        @Test
        @DisplayName("Bearer 리소스 호출: 필터 체인 정상 진행, ERROR 0건")
        void bearerResourceRequest_shouldPassThroughWithoutError() throws Exception {
            // Given
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            ListAppender<ILoggingEvent> appender = attachAppender(filterLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/organizations");
            request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs...");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then
                assertThat(chain.getRequest()).isNotNull();
                long errorCount = appender.list.stream()
                    .filter(e -> e.getLevel() == Level.ERROR)
                    .count();
                assertThat(errorCount).isZero();
            } finally {
                detachAppender(appender, filterLogger);
            }
        }

        @Test
        @DisplayName("Basic 인증 호출: 필터 체인 정상 진행, ERROR 0건")
        void basicAuthRequest_shouldPassThroughWithoutError() throws Exception {
            // Given
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            ListAppender<ILoggingEvent> appender = attachAppender(filterLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");
            request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then
                assertThat(chain.getRequest()).isNotNull();
                long errorCount = appender.list.stream()
                    .filter(e -> e.getLevel() == Level.ERROR)
                    .count();
                assertThat(errorCount).isZero();
            } finally {
                detachAppender(appender, filterLogger);
            }
        }

        @Test
        @DisplayName("세션 null + OIDC 쿠키: 예외 미발생, 필터 체인 정상 진행 (AC#1 핵심)")
        void oidcCookieWithNullSession_shouldNotThrowAndProceed() throws Exception {
            // Given — 기존 버그 재현 조건: OIDC 쿠키 있음, 세션 없음
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");

            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ACCESS_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("access-token-value"));
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ID_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("id-token-value"));

                // When & Then — 예외 미발생
                org.assertj.core.api.Assertions.assertThatNoException().isThrownBy(
                    () -> filter.doFilter(request, response, chain)
                );

                // 필터 체인 진행 확인
                assertThat(chain.getRequest()).isNotNull();

                // 인증 시도 없음
                verify(authenticationManager, never()).authenticate(any());
            }
        }

        @Test
        @DisplayName("세션 null + OIDC 쿠키: result=FAILURE 오탐 없음 (AC#2)")
        void oidcCookieWithNullSession_shouldNotProduceFailureAuditLog() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(eventLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ACCESS_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("access-token-value"));
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ID_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("id-token-value"));

                try {
                    // When
                    filter.doFilter(request, response, chain);

                    // Then — FAILURE 오탐 없음
                    boolean hasFailure = appender.list.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("result=FAILURE"));
                    assertThat(hasFailure)
                        .as("세션 없음 OIDC_COOKIE 경로에서 result=FAILURE가 발생하면 안 된다 (AC#2)")
                        .isFalse();

                    // NO_SESSION 기록 확인
                    boolean hasNoSession = appender.list.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("result=NO_SESSION"));
                    assertThat(hasNoSession)
                        .as("세션 없음은 result=NO_SESSION으로 기록되어야 한다")
                        .isTrue();
                } finally {
                    detachAppender(appender, eventLogger);
                }
            }
        }
    }

    // =========================================================
    // AC#4: rate-limiter 카운터 미증가 검증 (로그 기반)
    // =========================================================

    @Nested
    @DisplayName("AC#4: rate-limiter 오탐 방지 — logNoSession/logSkipped은 FAILURE 미기록")
    class RateLimiterOvertriggerScenario {

        @Test
        @DisplayName("세션 없음 이벤트는 result=FAILURE를 기록하지 않아 rate-limiter 카운터가 증가하지 않는다")
        void noSession_shouldNotTriggerFailureForRateLimiter() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(eventLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ACCESS_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("access-token-value"));
                cookieUtil.when(() -> CookieUtil.getCookieValue(any(), org.mockito.ArgumentMatchers.eq(CookieUtil.ID_TOKEN_NAME)))
                    .thenReturn(java.util.Optional.of("id-token-value"));

                try {
                    // When
                    filter.doFilter(request, response, chain);

                    // Then — FAILURE 없음 = rate-limiter 카운터 미증가 조건
                    long failureCount = appender.list.stream()
                        .filter(e -> e.getFormattedMessage().contains("result=FAILURE"))
                        .count();
                    assertThat(failureCount)
                        .as("세션 없음은 rate-limiter FAILURE로 집계되면 안 된다 (AC#4)")
                        .isZero();
                } finally {
                    detachAppender(appender, eventLogger);
                }
            }
        }

        @Test
        @DisplayName("CREDENTIAL_LOGIN 경로는 result=FAILURE를 기록하지 않아 rate-limiter 카운터가 증가하지 않는다")
        void credentialLogin_shouldNotTriggerFailureForRateLimiter() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> appender = attachAppender(eventLogger, Level.ALL);

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            try {
                // When
                filter.doFilter(request, response, chain);

                // Then
                long failureCount = appender.list.stream()
                    .filter(e -> e.getFormattedMessage().contains("result=FAILURE"))
                    .count();
                assertThat(failureCount)
                    .as("CREDENTIAL_LOGIN 경로는 rate-limiter FAILURE로 집계되면 안 된다 (AC#4)")
                    .isZero();
            } finally {
                detachAppender(appender, eventLogger);
            }
        }
    }

    // =========================================================
    // 헬퍼 메서드
    // =========================================================

    private ListAppender<ILoggingEvent> attachAppender(Logger logger, Level level) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(level);
        return appender;
    }

    private ListAppender<ILoggingEvent> attachAppender(Logger logger1, Logger logger2, Level level) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger1.addAppender(appender);
        logger1.setLevel(level);
        logger2.addAppender(appender);
        logger2.setLevel(level);
        return appender;
    }

    private void detachAppender(ListAppender<ILoggingEvent> appender, Logger... loggers) {
        for (Logger logger : loggers) {
            logger.detachAppender(appender);
        }
        appender.stop();
    }
}
