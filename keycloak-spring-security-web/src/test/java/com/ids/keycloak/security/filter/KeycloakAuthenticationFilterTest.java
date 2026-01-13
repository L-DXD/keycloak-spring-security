package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationFilterTest {

    @Mock
    private JwtDecoder jwtDecoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private KeycloakSessionManager sessionManager;

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
        filter = new KeycloakAuthenticationFilter(jwtDecoder, authenticationManager, objectMapper, sessionManager);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private Jwt createMockJwt(String subject) {
        return Jwt.withTokenValue(ID_TOKEN_VALUE)
            .header("alg", "RS256")
            .subject(subject)
            .build();
    }

    private KeycloakAuthentication createSuccessfulAuthentication() {
        KeycloakPrincipal principal = new KeycloakPrincipal(USER_SUB, Collections.emptyList(), Collections.emptyMap());
        KeycloakAuthentication auth = new KeycloakAuthentication(principal, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);
        auth.setAuthenticated(true);
        return auth;
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 유효한_토큰과_세션이_있으면_인증에_성공한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(jwtDecoder.decode(ID_TOKEN_VALUE)).thenReturn(createMockJwt(USER_SUB));

            KeycloakAuthentication successAuth = createSuccessfulAuthentication();
            when(authenticationManager.authenticate(any())).thenReturn(successAuth);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                verify(authenticationManager).authenticate(any(KeycloakAuthentication.class));
                verify(filterChain).doFilter(request, response);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
                assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(USER_SUB);
            }
        }

        @Test
        void 토큰_재발급_시_세션과_쿠키를_갱신한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(jwtDecoder.decode(ID_TOKEN_VALUE)).thenReturn(createMockJwt(USER_SUB));

            String newRefreshToken = "new-refresh-token";
            String newAccessToken = "new-access-token";
            String newIdToken = "new-id-token";

            KeycloakTokenInfo newTokens = KeycloakTokenInfo.builder()
                .refreshToken(newRefreshToken)
                .accessToken(newAccessToken)
                .idToken(newIdToken)
                .expireTime(3600)
                .build();

            KeycloakAuthentication successAuth = createSuccessfulAuthentication();
            successAuth.setDetails(newTokens);
            when(authenticationManager.authenticate(any())).thenReturn(successAuth);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                verify(sessionManager).saveRefreshToken(session, newRefreshToken);
                cookieUtil.verify(() -> CookieUtil.addTokenCookies(response, newAccessToken, 3600, newIdToken, 3600));
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            }
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void 세션이_없으면_쿠키를_삭제하고_인증을_시도하지_않는다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(null);

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
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(jwtDecoder.decode(ID_TOKEN_VALUE)).thenReturn(createMockJwt(USER_SUB));
            when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Authentication failed"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

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
        void ID_Token_디코딩_실패_시_unknown_principal로_인증을_시도한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(jwtDecoder.decode(ID_TOKEN_VALUE)).thenThrow(new JwtException("Invalid token"));

            KeycloakAuthentication successAuth = createSuccessfulAuthentication();
            when(authenticationManager.authenticate(any())).thenReturn(successAuth);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

                // When
                filter.doFilterInternal(request, response, filterChain);

                // Then
                verify(authenticationManager).authenticate(any(KeycloakAuthentication.class));
                verify(filterChain).doFilter(request, response);
            }
        }

        @Test
        void 일반_Exception_발생_시_SecurityContext를_비우고_쿠키를_삭제한다() throws Exception {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN_VALUE));
            when(jwtDecoder.decode(ID_TOKEN_VALUE)).thenThrow(new RuntimeException("Unexpected error"));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME))
                    .thenReturn(Optional.of(ID_TOKEN_VALUE));
                cookieUtil.when(() -> CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME))
                    .thenReturn(Optional.of(ACCESS_TOKEN_VALUE));

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