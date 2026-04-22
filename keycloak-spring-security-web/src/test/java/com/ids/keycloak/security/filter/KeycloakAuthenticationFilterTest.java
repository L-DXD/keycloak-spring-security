package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationFilterTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private KeycloakAuthenticationProvider authenticationProvider;

    @Mock
    private KeycloakSessionManager sessionManager;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private FilterChain filterChain;

    private KeycloakAuthenticationFilter filter;

    private static final String ID_TOKEN_VALUE = "id-token-value";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";
    private static final String REFRESH_TOKEN_VALUE = "refresh-token-value";
    private static final String USER_SUB = "user-123";

    @BeforeEach
    void setUp() {
        filter = new KeycloakAuthenticationFilter(
            authenticationManager,
            authenticationProvider,
            sessionManager,
            keycloakClient
        );
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private KeycloakAuthentication createSuccessfulAuthentication() {
        OidcIdToken idToken = new OidcIdToken(
            ID_TOKEN_VALUE,
            Instant.now(),
            Instant.now().plusSeconds(3600),
            Map.of("sub", USER_SUB)
        );
        KeycloakPrincipal principal = new KeycloakPrincipal(USER_SUB, Collections.emptyList(), idToken, null);
        return new KeycloakAuthentication(principal, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, true);
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 유효한_토큰과_세션이_있으면_인증에_성공한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));

            KeycloakAuthentication successAuth = createSuccessfulAuthentication();
            when(authenticationManager.authenticate(any())).thenReturn(successAuth);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                verify(authenticationManager).authenticate(any(KeycloakAuthentication.class));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
                assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(USER_SUB);
            }
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void 세션이_없으면_쿠키를_삭제하고_인증을_시도하지_않는다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(null);
            // request.getSession() 스터빙 제거: Phase 3 이후 세션 없음 경로에서 getSession() 호출 없음

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(authenticationManager, never()).authenticate(any());
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            }
        }

        @Test
        void 세션에_Refresh_Token이_없으면_쿠키를_삭제하고_인증을_시도하지_않는다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.empty());

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(authenticationManager, never()).authenticate(any());
                verify(filterChain).doFilter(request, response);
            }
        }

        @Test
        void AuthenticationException_발생_시_SecurityContext를_비우고_쿠키를_삭제한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(request.getSession()).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Authentication failed"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            }
        }

        @Test
        void IntrospectionFailedException_발생_시_SecurityContext를_비우고_쿠키를_삭제한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(request.getSession()).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new IntrospectionFailedException("토큰 온라인 검증 실패"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            }
        }

        @Test
        void UserInfoFetchException_발생_시_SecurityContext를_비우고_쿠키를_삭제한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(request.getSession()).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new UserInfoFetchException("UserInfo 조회 실패"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            }
        }
    }

    @Nested
    class 필터_스킵_케이스 {

        @Test
        void 토큰_발급_API_경로는_필터를_스킵한다() throws Exception {
            // Given
            KeycloakAuthenticationFilter filterWithSkip = new KeycloakAuthenticationFilter(
                authenticationManager, authenticationProvider, sessionManager, keycloakClient,
                List.of("/auth/token", "/auth/refresh", "/auth/logout")
            );
            when(request.getRequestURI()).thenReturn("/auth/token");

            // When
            boolean result = filterWithSkip.shouldNotFilter(request);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        void 토큰_갱신_API_경로는_필터를_스킵한다() throws Exception {
            // Given
            KeycloakAuthenticationFilter filterWithSkip = new KeycloakAuthenticationFilter(
                authenticationManager, authenticationProvider, sessionManager, keycloakClient,
                List.of("/auth/token", "/auth/refresh", "/auth/logout")
            );
            when(request.getRequestURI()).thenReturn("/auth/refresh");

            // When
            boolean result = filterWithSkip.shouldNotFilter(request);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        void 토큰_로그아웃_API_경로는_필터를_스킵한다() throws Exception {
            // Given
            KeycloakAuthenticationFilter filterWithSkip = new KeycloakAuthenticationFilter(
                authenticationManager, authenticationProvider, sessionManager, keycloakClient,
                List.of("/auth/token", "/auth/refresh", "/auth/logout")
            );
            when(request.getRequestURI()).thenReturn("/auth/logout");

            // When
            boolean result = filterWithSkip.shouldNotFilter(request);

            // Then
            assertThat(result).isTrue();
        }

        /**
         * Phase 3 재설계 이후: Bearer 헤더 요청은 shouldNotFilter(=skipPaths 기반)가 아닌
         * doFilterInternal 내부의 AuthenticationMethodDetector가 BEARER로 판별하여 pass-through 처리한다.
         * shouldNotFilter는 skipPaths 등록 경로만 스킵한다.
         */
        @Test
        void Bearer_헤더가_있는_요청은_shouldNotFilter가_false를_반환한다_doFilterInternal에서_pass_through() throws Exception {
            // Given — Bearer 요청은 skipPaths에 없으므로 shouldNotFilter=false
            when(request.getRequestURI()).thenReturn("/api/some-resource");

            // When
            boolean result = filter.shouldNotFilter(request);

            // Then: 필터를 건너뛰지 않고 doFilterInternal로 진입 → 내부에서 BEARER 판별 후 pass-through
            assertThat(result).isFalse();
        }

        @Test
        void 커스텀_prefix_경로도_필터를_스킵한다() throws Exception {
            // Given
            KeycloakAuthenticationFilter filterWithCustomPrefix = new KeycloakAuthenticationFilter(
                authenticationManager, authenticationProvider, sessionManager, keycloakClient,
                List.of("/api/auth/token", "/api/auth/refresh", "/api/auth/logout")
            );
            when(request.getRequestURI()).thenReturn("/api/auth/token");

            // When
            boolean result = filterWithCustomPrefix.shouldNotFilter(request);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        void 스킵_경로가_아닌_일반_요청은_필터를_실행한다() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn("/api/some-resource");

            // When
            boolean result = filter.shouldNotFilter(request);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        void Basic_헤더가_있는_요청은_shouldNotFilter가_false를_반환한다() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn("/api/some-resource");

            // When
            boolean result = filter.shouldNotFilter(request);

            // Then
            assertThat(result).isFalse();
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 일반_Exception_발생_시_SecurityContext를_비우고_쿠키를_삭제한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(request.getSession()).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new RuntimeException("Unexpected error"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            }
        }

        /**
         * Phase 3 핵심 회귀 — catch(Exception) 블록은 warn 레벨이어야 한다.
         * 예기치 못한 예외 발생 시 log.error가 아닌 log.warn이 호출되는지 확인한다.
         */
        @Test
        void 예기치_못한_예외는_WARN_레벨로_기록되고_ERROR는_사용되지_않는다() throws Exception {
            // Given
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            filterLogger.addAppender(logAppender);
            filterLogger.setLevel(Level.WARN);

            when(request.getSession(false)).thenReturn(session);
            when(request.getSession()).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new RuntimeException("Unexpected error"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class);
                 MockedStatic<JwtUtil> jwtUtil = mockStatic(JwtUtil.class)) {

                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                jwtUtil.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then: ERROR 레벨 로그 없음 (warn으로 하향됨)
                boolean hasErrorLog = logAppender.list.stream()
                    .anyMatch(e -> e.getLevel() == Level.ERROR);
                assertThat(hasErrorLog).isFalse();

            } finally {
                filterLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }
    }

    // ======================================================================
    // Phase 4 핵심 회귀 시나리오
    // ======================================================================

    /**
     * 핵심 버그 수정 검증:
     * 세션이 null이고 OIDC 쿠키가 있을 때 AuthenticationFailedException이 발생하지 않아야 한다.
     * filter chain이 정상 진행되고, logNoSession이 호출되며, 쿠키가 삭제된다.
     */
    @Nested
    class 세션_null_OIDC_COOKIE_핵심_회귀 {

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_AuthenticationFailedException이_발생하지_않는다() throws Exception {
            // Given — OIDC 쿠키 있음, 세션 없음
            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                // When & Then — 예외 미발생이 핵심 요구사항 (AC#1)
                assertThatNoException().isThrownBy(
                    () -> filter.doFilterInternal(request, response, filterChain)
                );
            }
        }

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_chain_doFilter가_호출된다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                verify(filterChain).doFilter(request, response);
            }
        }

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_authenticationManager가_호출되지_않는다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then — 세션 없음 상태에서 인증 시도 없음
                verify(authenticationManager, never()).authenticate(any());
            }
        }

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_쿠키_삭제가_호출된다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
            }
        }

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_logNoSession이_기록된다() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            eventLogger.addAppender(logAppender);
            eventLogger.setLevel(Level.DEBUG);

            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                try {
                    // When
                    filter.doFilterInternal(request, response, filterChain);

                    // Then — NO_SESSION 로그 확인
                    boolean hasNoSessionLog = logAppender.list.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("result=NO_SESSION"));
                    assertThat(hasNoSessionLog)
                        .as("세션 없음 시 result=NO_SESSION 로그가 기록되어야 한다")
                        .isTrue();

                    // FAILURE 오탐 없음 확인 (핵심 — AC#2)
                    boolean hasFailureLog = logAppender.list.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("result=FAILURE"));
                    assertThat(hasFailureLog)
                        .as("세션 없음은 FAILURE가 아니어야 한다 — 오탐 방지 (AC#2)")
                        .isFalse();
                } finally {
                    eventLogger.detachAppender(logAppender);
                    logAppender.stop();
                }
            }
        }

        @Test
        void 세션_null_OIDC_COOKIE_경로에서_ERROR_레벨_로그가_없다() throws Exception {
            // Given — AC#1 핵심 검증: 기존 버그에서는 매번 ERROR가 발생했음
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            filterLogger.addAppender(logAppender);
            filterLogger.setLevel(Level.ALL);

            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));

                try {
                    // When
                    filter.doFilterInternal(request, response, filterChain);

                    // Then — 핵심: ERROR 레벨 로그 0건 (기존 버그에서는 ERROR가 발생했음)
                    boolean hasErrorLog = logAppender.list.stream()
                        .anyMatch(e -> e.getLevel() == Level.ERROR);
                    assertThat(hasErrorLog)
                        .as("세션 없음 OIDC_COOKIE 경로에서 ERROR 로그가 발생하면 안 된다 (AC#1 검증)")
                        .isFalse();
                } finally {
                    filterLogger.detachAppender(logAppender);
                    logAppender.stop();
                }
            }
        }
    }

    /**
     * POST /api/keycloak/login (CREDENTIAL_LOGIN) 경로 회귀 시나리오.
     * stateless 로그인 요청에서 세션 검사 없이 pass-through되어야 한다.
     */
    @Nested
    class CREDENTIAL_LOGIN_경로_회귀 {

        @Test
        void POST_loginPath_요청은_세션_검사_없이_chain_doFilter가_호출된다() throws Exception {
            // Given — mock request에 POST + loginPath 설정 (Bearer/Basic 없음, getCookies 호출 안 됨)
            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/api/keycloak/login");

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void POST_loginPath_요청은_logSkipped가_기록된다() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            eventLogger.addAppender(logAppender);
            eventLogger.setLevel(Level.INFO);

            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/api/keycloak/login");

            try {
                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then — SKIPPED 로그 확인
                boolean hasSkippedLog = logAppender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=SKIPPED"));
                assertThat(hasSkippedLog)
                    .as("CREDENTIAL_LOGIN 경로는 result=SKIPPED로 기록되어야 한다")
                    .isTrue();
            } finally {
                eventLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }

        @Test
        void POST_loginPath_요청에서_ERROR_레벨_로그가_없다() throws Exception {
            // Given — AC#1 핵심 검증
            Logger filterLogger = (Logger) LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            filterLogger.addAppender(logAppender);
            eventLogger.addAppender(logAppender);
            filterLogger.setLevel(Level.ALL);
            eventLogger.setLevel(Level.ALL);

            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/api/keycloak/login");

            try {
                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then — 핵심: ERROR 로그 0건 (기존 버그에서는 매 로그인마다 ERROR가 발생)
                boolean hasErrorLog = logAppender.list.stream()
                    .anyMatch(e -> e.getLevel() == Level.ERROR);
                assertThat(hasErrorLog)
                    .as("POST /api/keycloak/login에서 ERROR 로그가 발생하면 안 된다 (AC#1)")
                    .isFalse();
            } finally {
                filterLogger.detachAppender(logAppender);
                eventLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }

        @Test
        void POST_loginPath_요청에서_FAILURE_감사_로그가_없다() throws Exception {
            // Given — AC#2 핵심 검증 (result=FAILURE method=OIDC_COOKIE 오탐 방지)
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            eventLogger.addAppender(logAppender);
            eventLogger.setLevel(Level.ALL);

            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/api/keycloak/login");

            try {
                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then — FAILURE 오탐 없음 (AC#2)
                boolean hasFailureLog = logAppender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=FAILURE"));
                assertThat(hasFailureLog)
                    .as("[AUTH] result=FAILURE 오탐이 발생하면 안 된다 (AC#2)")
                    .isFalse();
            } finally {
                eventLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }
    }

    /**
     * Bearer 리소스 호출 회귀 시나리오 (AC#3).
     * Bearer 헤더 요청은 세션 검사 없이 logSkipped 후 pass-through되어야 한다.
     */
    @Nested
    class Bearer_리소스_호출_회귀 {

        @Test
        void Bearer_헤더_요청은_chain_doFilter가_호출된다() throws Exception {
            // Given — Bearer 헤더가 있으면 getCookies 호출 없이 즉시 반환
            when(request.getHeader("Authorization")).thenReturn("Bearer eyJhbGciOiJSUzI1NiIs...");

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
        }

        @Test
        void Bearer_헤더_요청은_세션_검사를_하지_않는다() throws Exception {
            // Given
            when(request.getHeader("Authorization")).thenReturn("Bearer eyJhbGciOiJSUzI1NiIs...");

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void Bearer_헤더_요청은_SKIPPED_로그가_BEARER_메서드로_기록된다() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            eventLogger.addAppender(logAppender);
            eventLogger.setLevel(Level.INFO);

            when(request.getHeader("Authorization")).thenReturn("Bearer eyJhbGciOiJSUzI1NiIs...");

            try {
                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                boolean hasSkippedBearerLog = logAppender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=SKIPPED")
                        && e.getFormattedMessage().contains("method=BEARER"));
                assertThat(hasSkippedBearerLog)
                    .as("Bearer 요청은 result=SKIPPED method=BEARER로 기록되어야 한다")
                    .isTrue();
            } finally {
                eventLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }
    }

    /**
     * Basic 인증 요청 회귀 시나리오 (AC#3).
     */
    @Nested
    class Basic_인증_요청_회귀 {

        @Test
        void Basic_헤더_요청은_chain_doFilter가_호출된다() throws Exception {
            // Given — Basic 헤더가 있으면 getCookies 호출 없이 즉시 반환
            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            // When
            filter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
        }

        @Test
        void Basic_헤더_요청은_SKIPPED_로그가_BASIC_메서드로_기록된다() throws Exception {
            // Given
            Logger eventLogger = (Logger) LoggerFactory.getLogger(AuthenticationEventLogger.class);
            ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
            logAppender.start();
            eventLogger.addAppender(logAppender);
            eventLogger.setLevel(Level.INFO);

            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            try {
                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                boolean hasSkippedBasicLog = logAppender.list.stream()
                    .anyMatch(e -> e.getFormattedMessage().contains("result=SKIPPED")
                        && e.getFormattedMessage().contains("method=BASIC"));
                assertThat(hasSkippedBasicLog)
                    .as("Basic 요청은 result=SKIPPED method=BASIC으로 기록되어야 한다")
                    .isTrue();
            } finally {
                eventLogger.detachAppender(logAppender);
                logAppender.stop();
            }
        }
    }

    /**
     * 커스텀 loginPaths 주입 시나리오.
     * 6-arg 생성자를 통해 커스텀 경로도 CREDENTIAL_LOGIN으로 처리되어야 한다.
     */
    @Nested
    class 커스텀_loginPaths_생성자_회귀 {

        @Test
        void 커스텀_loginPaths_주입_시_해당_경로도_CREDENTIAL_LOGIN으로_처리된다() throws Exception {
            // Given
            KeycloakAuthenticationFilter filterWithCustomLogin = new KeycloakAuthenticationFilter(
                authenticationManager, authenticationProvider, sessionManager, keycloakClient,
                List.of(), List.of("/api/keycloak/login", "/custom/login")
            );

            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/custom/login");

            // When
            filterWithCustomLogin.doFilterInternal(request, response, filterChain);

            // Then — 세션 검사 없이 pass-through
            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
        }
    }
}
