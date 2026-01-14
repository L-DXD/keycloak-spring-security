package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.Map;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MdcAuthenticationFilterTest {

    @Mock
    private LoggingContextAccessor contextAccessor;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private KeycloakSecurityProperties securityProperties;
    private MdcAuthenticationFilter mdcAuthenticationFilter;

    @BeforeEach
    void setUp() {
        securityProperties = new KeycloakSecurityProperties();
        mdcAuthenticationFilter = new MdcAuthenticationFilter(contextAccessor, securityProperties);
        SecurityContextHolder.clearContext();
    }

    @Nested
    class 정상_케이스 {

        @Test
        void KeycloakPrincipal_로그인_시_사용자_정보가_MDC에_저장된다() throws Exception {
            // Given
            Map<String, Object> attributes = Map.of(
                    "sub", "user-123",
                    "preferred_username", "testuser",
                    "sid", "session-abc"
            );
            KeycloakPrincipal principal = new KeycloakPrincipal("user-123", Collections.emptyList(), attributes);
            Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);

            // When
            mdcAuthenticationFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(LoggingContextKeys.USER_ID, "user-123");
            verify(contextAccessor).put(LoggingContextKeys.USERNAME, "testuser");
            verify(contextAccessor).put(LoggingContextKeys.SESSION_ID, "session-abc");
            verify(filterChain).doFilter(request, response);
        }

        @Test
        void 설정이_비활성화된_필드는_MDC에_저장되지_않는다() throws Exception {
            // Given
            securityProperties.getLogging().setIncludeSessionId(false);
            
            Map<String, Object> attributes = Map.of(
                    "sub", "user-123",
                    "sid", "session-abc"
            );
            KeycloakPrincipal principal = new KeycloakPrincipal("user-123", Collections.emptyList(), attributes);
            Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);

            // When
            mdcAuthenticationFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor).put(LoggingContextKeys.USER_ID, "user-123");
            verify(contextAccessor, never()).put(eq(LoggingContextKeys.SESSION_ID), anyString());
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void 인증_정보가_없으면_MDC에_아무것도_저장하지_않는다() throws Exception {
            // Given
            SecurityContextHolder.clearContext();

            // When
            mdcAuthenticationFilter.doFilter(request, response, filterChain);

            // Then
            verify(contextAccessor, never()).put(anyString(), anyString());
            verify(filterChain).doFilter(request, response);
        }
    }
}
