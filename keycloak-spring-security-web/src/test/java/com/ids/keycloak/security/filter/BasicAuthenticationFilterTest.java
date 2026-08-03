package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

@ExtendWith(MockitoExtension.class)
class BasicAuthenticationFilterTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private BasicAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new BasicAuthenticationFilter(authenticationManager);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    class Basic_헤더_없는_경우 {

        @Test
        void Authorization_헤더가_없으면_다음_필터로_넘긴다() throws Exception {
            when(request.getHeader("Authorization")).thenReturn(null);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void Bearer_토큰이면_다음_필터로_넘긴다() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer some-token");

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
        }
    }

    @Nested
    class Basic_헤더_있는_경우 {

        @Test
        void 유효한_Basic_헤더로_인증_성공시_SecurityContext에_설정된다() throws Exception {
            String credentials = Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);

            OidcIdToken idToken = new OidcIdToken(
                "id-token", Instant.now(), Instant.now().plusSeconds(3600),
                Map.of("sub", "user-123")
            );
            KeycloakPrincipal principal = new KeycloakPrincipal("user-123", Collections.emptyList(), idToken, null);
            BasicAuthenticationToken authenticated = new BasicAuthenticationToken(principal, "id-token", "access-token");

            when(authenticationManager.authenticate(any(BasicAuthenticationToken.class)))
                .thenReturn(authenticated);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
        }

        @Test
        void 인증_실패시_SecurityContext가_비워진다() throws Exception {
            String credentials = Base64.getEncoder().encodeToString("user:wrongpass".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);

            when(authenticationManager.authenticate(any(BasicAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void 콜론이_없는_잘못된_형식이면_인증을_시도하지_않는다() throws Exception {
            String credentials = Base64.getEncoder().encodeToString("invalidformat".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void 잘못된_Base64면_인증을_시도하지_않는다() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Basic !!!invalid-base64!!!");

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void 비밀번호에_콜론이_포함되어도_정상_파싱된다() throws Exception {
            String credentials = Base64.getEncoder().encodeToString("user:pass:with:colons".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);

            OidcIdToken idToken = new OidcIdToken(
                "id-token", Instant.now(), Instant.now().plusSeconds(3600),
                Map.of("sub", "user-123")
            );
            KeycloakPrincipal principal = new KeycloakPrincipal("user-123", Collections.emptyList(), idToken, null);
            BasicAuthenticationToken authenticated = new BasicAuthenticationToken(principal, "id-token", "access-token");

            when(authenticationManager.authenticate(any(BasicAuthenticationToken.class)))
                .thenReturn(authenticated);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        }
    }

    /**
     * 23d36d6: 앞단 필터(핸드오프 필터 등)가 이미 인증된 컨텍스트를 세워둔 상태에서 이 필터의
     * Basic 인증 시도가 실패(형식 오류/자격증명 실패/Base64 오류)해도, 그 인증을 지우면 안 된다.
     * {@code clearContextUnlessAlreadyAuthenticated()}가 관여하는 3개 경로 모두 검증한다.
     */
    @Nested
    class 이미_인증된_컨텍스트_보존 {

        private TestingAuthenticationToken setExistingAuthentication() {
            TestingAuthenticationToken existing = new TestingAuthenticationToken("front-user", "N/A");
            existing.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(existing);
            return existing;
        }

        @Test
        void 콜론없는_형식오류에서도_이미인증된_컨텍스트는_유지된다() throws Exception {
            TestingAuthenticationToken existing = setExistingAuthentication();
            String credentials = Base64.getEncoder().encodeToString("invalidformat".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existing);
        }

        @Test
        void 자격증명_실패에서도_이미인증된_컨텍스트는_유지된다() throws Exception {
            TestingAuthenticationToken existing = setExistingAuthentication();
            String credentials = Base64.getEncoder().encodeToString("user:wrongpass".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);
            when(authenticationManager.authenticate(any(BasicAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existing);
        }

        @Test
        void 잘못된_Base64에서도_이미인증된_컨텍스트는_유지된다() throws Exception {
            TestingAuthenticationToken existing = setExistingAuthentication();
            when(request.getHeader("Authorization")).thenReturn("Basic !!!invalid-base64!!!");

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(authenticationManager, never()).authenticate(any());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existing);
        }

        @Test
        void Anonymous_인증만_있는_경우는_이미인증됨으로_보지_않고_그대로_비운다() throws Exception {
            AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", Collections.singletonList(() -> "ROLE_ANONYMOUS"));
            SecurityContextHolder.getContext().setAuthentication(anonymous);

            String credentials = Base64.getEncoder().encodeToString("user:wrongpass".getBytes(StandardCharsets.UTF_8));
            when(request.getHeader("Authorization")).thenReturn("Basic " + credentials);
            when(authenticationManager.authenticate(any(BasicAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void 인증되지않은_컨텍스트만_있는_경우도_이미인증됨으로_보지_않고_그대로_비운다() throws Exception {
            TestingAuthenticationToken notAuthenticated = new TestingAuthenticationToken("front-user", "N/A");
            notAuthenticated.setAuthenticated(false);
            SecurityContextHolder.getContext().setAuthentication(notAuthenticated);

            when(request.getHeader("Authorization")).thenReturn("Basic !!!invalid-base64!!!");

            filter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }
}
