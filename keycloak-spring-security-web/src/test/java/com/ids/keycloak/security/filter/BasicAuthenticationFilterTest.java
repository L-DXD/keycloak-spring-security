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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
}
