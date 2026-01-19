package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Collections;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

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
        KeycloakPrincipal principal = new KeycloakPrincipal(USER_SUB, Collections.emptyList(), Collections.emptyMap());
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
            when(request.getSession()).thenReturn(session);

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
    }
}
