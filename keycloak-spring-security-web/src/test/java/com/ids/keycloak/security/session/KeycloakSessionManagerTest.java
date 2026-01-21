package com.ids.keycloak.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.session.FindByIndexNameSessionRepository;

@ExtendWith(MockitoExtension.class)
class KeycloakSessionManagerTest {

    @Mock
    private HttpSession session;

    private KeycloakSessionManager manager;

    private static final String REFRESH_TOKEN = "refresh-token-abc";
    private static final String KEYCLOAK_SID = "keycloak-sid-123";
    private static final String PRINCIPAL_NAME = "user-123";

    @BeforeEach
    void setUp() {
        manager = new KeycloakSessionManager();
    }

    @Nested
    class 정상_케이스 {

        @Test
        void Refresh_Token을_세션에_저장하고_조회한다() {
            // Given
            when(session.getAttribute(KeycloakSessionManager.REFRESH_TOKEN_ATTR)).thenReturn(REFRESH_TOKEN);

            // When - 저장
            manager.saveRefreshToken(session, REFRESH_TOKEN);

            // Then - 저장 검증
            verify(session).setAttribute(KeycloakSessionManager.REFRESH_TOKEN_ATTR, REFRESH_TOKEN);

            // When - 조회
            Optional<String> result = manager.getRefreshToken(session);

            // Then - 조회 검증
            assertThat(result).isPresent().contains(REFRESH_TOKEN);
        }

        @Test
        void Keycloak_Session_ID를_세션에_저장하고_조회한다() {
            // Given
            when(session.getAttribute(KeycloakSessionManager.KEYCLOAK_SESSION_ID_ATTR)).thenReturn(KEYCLOAK_SID);

            // When - 저장
            manager.saveKeycloakSessionId(session, KEYCLOAK_SID);

            // Then - 저장 검증
            verify(session).setAttribute(KeycloakSessionManager.KEYCLOAK_SESSION_ID_ATTR, KEYCLOAK_SID);

            // When - 조회
            Optional<String> result = manager.getKeycloakSessionId(session);

            // Then - 조회 검증
            assertThat(result).isPresent().contains(KEYCLOAK_SID);
        }

        @Test
        void Principal_Name을_세션에_저장한다() {
            // When
            manager.savePrincipalName(session, PRINCIPAL_NAME);

            // Then
            verify(session).setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, PRINCIPAL_NAME);
        }

        @Test
        void 세션을_무효화한다() {
            // Given
            when(session.getId()).thenReturn("session-id");

            // When
            manager.invalidateSession(session);

            // Then
            verify(session).invalidate();
        }

        @Test
        void Refresh_Token을_세션에서_삭제한다() {
            // When
            manager.removeRefreshToken(session);

            // Then
            verify(session).removeAttribute(KeycloakSessionManager.REFRESH_TOKEN_ATTR);
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 세션이_null이면_저장_시_예외없이_처리된다() {
            // When & Then
            assertDoesNotThrow(() -> manager.saveRefreshToken(null, REFRESH_TOKEN));
            assertDoesNotThrow(() -> manager.saveKeycloakSessionId(null, KEYCLOAK_SID));
            assertDoesNotThrow(() -> manager.savePrincipalName(null, PRINCIPAL_NAME));
        }

        @Test
        void 세션이_null이면_조회_시_빈_Optional을_반환한다() {
            // When
            Optional<String> refreshToken = manager.getRefreshToken(null);
            Optional<String> keycloakSid = manager.getKeycloakSessionId(null);

            // Then
            assertThat(refreshToken).isEmpty();
            assertThat(keycloakSid).isEmpty();
        }

        @Test
        void 세션이_null이면_무효화_시_예외없이_처리된다() {
            // When & Then
            assertDoesNotThrow(() -> manager.invalidateSession(null));
        }

        @Test
        void 세션이_null이면_삭제_시_예외없이_처리된다() {
            // When & Then
            assertDoesNotThrow(() -> manager.removeRefreshToken(null));
        }

        @Test
        void Refresh_Token이_null이면_저장하지_않는다() {
            // When
            manager.saveRefreshToken(session, null);

            // Then
            verify(session, never()).setAttribute(KeycloakSessionManager.REFRESH_TOKEN_ATTR, null);
        }

        @Test
        void Keycloak_Session_ID가_null이면_저장하지_않는다() {
            // When
            manager.saveKeycloakSessionId(session, null);

            // Then
            verify(session, never()).setAttribute(KeycloakSessionManager.KEYCLOAK_SESSION_ID_ATTR, null);
        }

        @Test
        void Principal_Name이_null이면_저장하지_않는다() {
            // When
            manager.savePrincipalName(session, null);

            // Then
            verify(session, never()).setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, null);
        }

        @Test
        void 세션에_Refresh_Token이_없으면_빈_Optional을_반환한다() {
            // Given
            when(session.getAttribute(KeycloakSessionManager.REFRESH_TOKEN_ATTR)).thenReturn(null);

            // When
            Optional<String> result = manager.getRefreshToken(session);

            // Then
            assertThat(result).isEmpty();
        }
    }
}
