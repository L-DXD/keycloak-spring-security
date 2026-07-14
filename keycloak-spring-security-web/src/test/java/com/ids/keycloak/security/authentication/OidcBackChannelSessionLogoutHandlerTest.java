package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ids.keycloak.security.util.LogMaskingUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
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

    /**
     * Advisory 5 리뷰 대응: "로그에 토큰/식별자 원문이 안 나온다"를 실제로 검증하는 테스트가
     * 없었던 완료기준 미충족을 해소한다. Logback {@link ListAppender}로 핸들러가 실제로 남기는
     * 로그를 캡처하여, sub/sid/jti 원문이 어떤 레벨에서도 노출되지 않음을 검증한다.
     */
    @Nested
    class 로그_마스킹_검증 {

        private static final String JTI = "logout-token-jti-9876543210";

        private Logger handlerLogger;
        private ListAppender<ILoggingEvent> logAppender;

        @BeforeEach
        void setUpLogCapture() {
            handlerLogger = (Logger) LoggerFactory.getLogger(OidcBackChannelSessionLogoutHandler.class);
            logAppender = new ListAppender<>();
            logAppender.start();
            handlerLogger.addAppender(logAppender);
            // 요구사항: DEBUG/TRACE 레벨까지 활성화한 상태에서도 원문 미출력을 검증
            handlerLogger.setLevel(Level.ALL);
        }

        @AfterEach
        void tearDownLogCapture() {
            handlerLogger.detachAppender(logAppender);
            logAppender.stop();
        }

        private List<String> formattedMessages() {
            return logAppender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .collect(Collectors.toList());
        }

        @Test
        void SID_매칭_삭제_경로에서_원문_subject_sid_jti가_로그에_노출되지_않는다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getId()).thenReturn(JTI);
            when(logoutToken.getSubject()).thenReturn(SUBJECT);
            when(logoutToken.getSessionId()).thenReturn(KEYCLOAK_SID);

            Session sessionA = mock(Session.class);
            when(sessionA.getAttribute(OidcBackChannelSessionLogoutHandler.KEYCLOAK_SESSION_ID_ATTR))
                .thenReturn(KEYCLOAK_SID);
            Map<String, Session> sessions = new HashMap<>();
            sessions.put(SESSION_A_ID, sessionA);
            when(sessionRepository.findByPrincipalName(SUBJECT)).thenReturn(sessions);

            // When
            handler.logout(request, response, authentication);

            // Then — 원문 미노출
            List<String> messages = formattedMessages();
            assertThat(messages).isNotEmpty();
            assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
            assertThat(messages).noneMatch(m -> m.contains(KEYCLOAK_SID));
            assertThat(messages).noneMatch(m -> m.contains(JTI));

            // 마스킹된 형태로는 실제로 기록됨 — 어서션이 무력화(로그 자체가 없어 통과)되지 않았음을 보장
            assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(SUBJECT)));
            assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(KEYCLOAK_SID)));
            assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(JTI)));
        }

        @Test
        void 전체_세션_삭제_경로_SID_없음_에서도_원문_subject가_로그에_노출되지_않는다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getId()).thenReturn(JTI);
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
            List<String> messages = formattedMessages();
            assertThat(messages).noneMatch(m -> m.contains(SUBJECT));
            assertThat(messages).noneMatch(m -> m.contains(JTI));
            assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(SUBJECT)));
        }

        @Test
        void OidcLogoutToken을_추출할_수_없는_경로에서도_전달된_원문_문자열이_로그에_없다() {
            // Given — principal/credentials에 실제 JWT 유사 문자열이 들어와도 그대로 로그에 남으면 안 된다
            String jwtLikeCredential = "eyJhbGciOiJSUzI1NiJ9.not-a-real-token-but-jwt-shaped.sig";
            when(authentication.getPrincipal()).thenReturn(jwtLikeCredential);
            when(authentication.getCredentials()).thenReturn("also-not-a-token");

            // When
            handler.logout(request, response, authentication);

            // Then
            List<String> messages = formattedMessages();
            assertThat(messages).noneMatch(m -> m.contains(jwtLikeCredential));
        }

        @Test
        void Subject가_null인_실패_경로에서도_sid와_jti는_마스킹된_형태로만_기록된다() {
            // Given
            when(authentication.getPrincipal()).thenReturn(logoutToken);
            when(logoutToken.getId()).thenReturn(JTI);
            when(logoutToken.getSubject()).thenReturn(null);
            when(logoutToken.getSessionId()).thenReturn(KEYCLOAK_SID);

            // When
            handler.logout(request, response, authentication);

            // Then — subject 관련 처리는 중단되지만, 그 전에 기록된 jti/sid 로그도 원문이 없어야 한다
            List<String> messages = formattedMessages();
            assertThat(messages).noneMatch(m -> m.contains(JTI));
            assertThat(messages).noneMatch(m -> m.contains(KEYCLOAK_SID));
            assertThat(messages).anyMatch(m -> m.contains(LogMaskingUtil.maskIdentifier(KEYCLOAK_SID)));
        }
    }
}
