package com.ids.keycloak.security.authentication;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

@ExtendWith(MockitoExtension.class)
class OidcBackChannelSessionLogoutHandlerTest {

    @Mock
    private FindByIndexNameSessionRepository<Session> sessionRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private Authentication authentication;

    @Mock
    private OidcLogoutToken logoutToken;

    private OidcBackChannelSessionLogoutHandler handler;

    private static final String SUBJECT = "user-123";
    private static final String KEYCLOAK_SID = "keycloak-session-abc";
    private static final String SESSION_A_ID = "spring-session-a";
    private static final String SESSION_B_ID = "spring-session-b";

    @BeforeEach
    void setUp() {
        handler = new OidcBackChannelSessionLogoutHandler(sessionRepository);
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 로그아웃_토큰에_SID가_있으면_해당_세션만_삭제한다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(KEYCLOAK_SID);

            Session sessionA = mock(Session.class);
            Session sessionB = mock(Session.class);
            when(sessionA.getAttribute(OidcBackChannelSessionLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
                .thenReturn(KEYCLOAK_SID);
            when(sessionB.getAttribute(OidcBackChannelSessionLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
                .thenReturn("other-sid");

            Map<String, Session> sessions = new HashMap<>();
            sessions.put(SESSION_A_ID, sessionA);
            sessions.put(SESSION_B_ID, sessionB);
            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(sessions);

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository).deleteById(SESSION_A_ID);
            verify(sessionRepository, never()).deleteById(SESSION_B_ID);
        }

        @Test
        void 로그아웃_토큰에_SID가_없으면_사용자의_모든_세션을_삭제한다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(null);

            Session sessionA = mock(Session.class);
            Session sessionB = mock(Session.class);

            Map<String, Session> sessions = new HashMap<>();
            sessions.put(SESSION_A_ID, sessionA);
            sessions.put(SESSION_B_ID, sessionB);
            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(sessions);

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository).deleteById(SESSION_A_ID);
            verify(sessionRepository).deleteById(SESSION_B_ID);
        }

        @Test
        void OidcLogoutToken이_credentials에_있어도_정상_추출된다() {
            // Given
            when(authentication.getPrincipal()).thenReturn("not-a-token");
            when(authentication.getCredentials()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(null);

            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(new HashMap<>());

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository).findByPrincipalName(SUBJECT);
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void Authentication이_null이면_처리를_스킵한다() {
            // When
            handler.logout(request, response, null);

            // Then
            verify(sessionRepository, never()).findByPrincipalName(SUBJECT);
        }

        @Test
        void OidcLogoutToken을_추출할_수_없으면_처리를_스킵한다() {
            // Given
            when(authentication.getPrincipal()).thenReturn("not-a-token");
            when(authentication.getCredentials()).thenReturn("also-not-a-token");

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository, never()).findByPrincipalName(SUBJECT);
        }

        @Test
        void Subject가_null이면_처리를_스킵한다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(null);

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository, never()).findByPrincipalName(SUBJECT);
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void SID에_매칭되는_세션이_없어도_예외없이_처리된다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(KEYCLOAK_SID);

            Session sessionA = mock(Session.class);
            when(sessionA.getAttribute(OidcBackChannelSessionLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
                .thenReturn("different-sid");

            Map<String, Session> sessions = new HashMap<>();
            sessions.put(SESSION_A_ID, sessionA);
            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(sessions);

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository, never()).deleteById(SESSION_A_ID);
        }

        @Test
        void 사용자_세션이_없으면_삭제없이_종료한다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(null);

            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(new HashMap<>());

            // When
            handler.logout(request, response, authentication);

            // Then
            verify(sessionRepository).findByPrincipalName(SUBJECT);
            verify(sessionRepository, never()).deleteById(SESSION_A_ID);
            verify(sessionRepository, never()).deleteById(SESSION_B_ID);
        }
    }
}
