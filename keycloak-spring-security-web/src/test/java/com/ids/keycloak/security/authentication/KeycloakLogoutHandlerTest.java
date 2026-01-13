package com.ids.keycloak.security.authentication;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class KeycloakLogoutHandlerTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    @Mock
    private KeycloakSessionManager sessionManager;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private KeycloakLogoutHandler handler;

    private static final String REFRESH_TOKEN = "test-refresh-token";

    @BeforeEach
    void setUp() {
        handler = new KeycloakLogoutHandler(keycloakClient, sessionManager);
    }

    @Nested
    class 로그아웃_테스트 {

        @Test
        void 로그아웃_시_Keycloak_서버에_요청을_보내고_세션과_쿠키를_정리한다() {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When
                handler.logout(request, response, null);

                // Then
                verify(keycloakClient.auth()).logout(REFRESH_TOKEN);
                verify(sessionManager).invalidateSession(session);
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
            }
        }

        @Test
        void 세션에_Refresh_Token이_없어도_세션_무효화와_쿠키_삭제는_수행한다() {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.empty());

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When
                handler.logout(request, response, null);

                // Then
                verify(keycloakClient.auth(), never()).logout(anyString());
                verify(sessionManager).invalidateSession(session);
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
            }
        }

        @Test
        void Keycloak_서버_로그아웃_실패_시에도_로컬_로그아웃_처리는_계속한다() {
            // Given
            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.getRefreshToken(session)).thenReturn(Optional.of(REFRESH_TOKEN));

            var authClient = keycloakClient.auth();
            doThrow(new RuntimeException("Keycloak server error"))
                .when(authClient).logout(REFRESH_TOKEN);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When & Then - 예외가 전파되지 않음
                assertDoesNotThrow(() -> handler.logout(request, response, null));

                verify(sessionManager).invalidateSession(session);
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
            }
        }

        @Test
        void 세션이_null이면_Keycloak_서버_로그아웃과_세션_무효화를_건너뛰고_쿠키만_삭제한다() {
            // Given
            when(request.getSession(false)).thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When
                handler.logout(request, response, null);

                // Then
                verify(sessionManager, never()).getRefreshToken(session);
                verify(sessionManager, never()).invalidateSession(session);
                verify(keycloakClient.auth(), never()).logout(anyString());
                cookieUtil.verify(() -> CookieUtil.deleteAllTokenCookies(response));
            }
        }
    }
}
