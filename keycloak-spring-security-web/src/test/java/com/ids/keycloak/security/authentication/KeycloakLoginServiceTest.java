package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.exception.TokenBindingException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * {@link KeycloakLoginService}의 프로그래밍 방식 로그인 파사드 동작을 검증한다.
 *
 * <p>핵심 불변식(choke point): {@code authenticate(...)}는 반드시
 * {@link KeycloakAuthenticationProvider#createAuthenticatedToken(String, String)}을 경유해야
 * 하며, 검증 실패 시 그 예외가 그대로 전파되고 어떤 SecurityContext/쿠키/세션도 세워지지 않아야
 * 한다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakLoginServiceTest {

    @Mock
    private KeycloakAuthenticationProvider authenticationProvider;

    @Mock
    private KeycloakSessionManager sessionManager;

    @Mock
    private SecurityContextRepository securityContextRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession existingSession;

    @Mock
    private HttpSession newSession;

    private KeycloakLoginService loginService;

    private static final String ID_TOKEN_VALUE = "id-token-value";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";
    private static final String REFRESH_TOKEN_VALUE = "refresh-token-value";
    private static final String USER_SUB = "user-123";
    private static final String KEYCLOAK_SID = "keycloak-sid-abc";

    @BeforeEach
    void setUp() {
        loginService = new KeycloakLoginService(authenticationProvider, sessionManager, securityContextRepository);
        SecurityContextHolder.clearContext();
    }

    private Authentication createSuccessfulAuthentication(boolean withSid) {
        Map<String, Object> claims = withSid
            ? Map.of("sub", USER_SUB, "sid", KEYCLOAK_SID)
            : Map.of("sub", USER_SUB);
        OidcIdToken idToken = new OidcIdToken(
            ID_TOKEN_VALUE, Instant.now(), Instant.now().plusSeconds(3600), claims);
        KeycloakPrincipal principal = new KeycloakPrincipal(USER_SUB, Collections.emptyList(), idToken, null);
        return new KeycloakAuthentication(principal, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, true);
    }

    @Nested
    class 검증_경유_choke_point {

        @Test
        void authenticate는_KeycloakAuthenticationProvider의_createAuthenticatedToken을_경유한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response,
                    KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                verify(authenticationProvider).createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);
            }
        }

        @Test
        void 검증_실패시_예외가_그대로_전파된다() {
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenThrow(new TokenBindingException("ID Token/UserInfo 결합 검증 실패"));

            assertThatThrownBy(() -> loginService.authenticate(
                request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE)))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("결합 검증 실패");
        }

        @Test
        void 검증_실패시_SecurityContext가_세워지지_않는다() {
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenThrow(new TokenBindingException("결합 검증 실패"));

            assertThatThrownBy(() -> loginService.authenticate(
                request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE)))
                .isInstanceOf(TokenBindingException.class);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void 검증_실패시_요청_응답_세션관리자에_아무_부작용도_없다() {
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenThrow(new TokenBindingException("결합 검증 실패"));

            assertThatThrownBy(() -> loginService.authenticate(
                request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE)))
                .isInstanceOf(TokenBindingException.class);

            // 예외가 검증 단계(1번)에서 즉시 전파되므로 이후 단계(세션 회전/저장/쿠키 발급)는
            // 전혀 실행되지 않아야 한다.
            verifyNoInteractions(request);
            verifyNoInteractions(response);
            verifyNoInteractions(sessionManager);
            verifyNoInteractions(securityContextRepository);
        }
    }

    @Nested
    class 성공시_SecurityContext_설정 {

        @Test
        void 인증_성공시_SecurityContextHolder에_Authentication이_설정된다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            Authentication expected = createSuccessfulAuthentication(true);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(expected);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                Authentication result = loginService.authenticate(
                    request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                assertThat(result).isSameAs(expected);
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expected);
            }
        }

        @Test
        void 인증_성공시_주입된_SecurityContextRepository에_saveContext가_호출된다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            Authentication expected = createSuccessfulAuthentication(true);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(expected);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
                verify(securityContextRepository).saveContext(captor.capture(), eq(request), eq(response));
                assertThat(captor.getValue().getAuthentication()).isSameAs(expected);
            }
        }

        @Test
        void 인증_성공시_토큰_쿠키가_발급된다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                // Access Token이 Opaque(비-JWT)이므로 ID Token의 maxAge(300)로 대체된다.
                cookieUtil.verify(() -> CookieUtil.addTokenCookies(
                    response, ACCESS_TOKEN_VALUE, 300, ID_TOKEN_VALUE, 300));
            }
        }

        @Test
        void 인증_성공시_RefreshToken_PrincipalName_sid가_세션에_저장된다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response,
                    KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE));

                // H-3/H-C: 개별 save* 호출이 아니라 KeycloakSessionManager로 추출된 공통 헬퍼
                // syncReLoginArtifacts를 경유해 Refresh Token/Principal Name/Keycloak Session ID가
                // 함께 동기화된다.
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);
            }
        }
    }

    @Nested
    class 세션_고정_방지 {

        @Test
        void 기존_세션이_있으면_changeSessionId로_회전한다() {
            when(request.getSession(false)).thenReturn(existingSession);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                verify(request).changeSessionId();
            }
        }

        @Test
        void 기존_세션이_없으면_changeSessionId를_호출하지_않는다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                verify(request, never()).changeSessionId();
            }
        }

        @Test
        void Back_Channel_인덱싱을_위해_세션이_없어도_새로_생성한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                verify(request).getSession(true);
                // Back-Channel 인덱싱을 위한 Principal Name 저장은 공통 헬퍼 syncReLoginArtifacts를
                // 경유한다(H-3/H-C). 이 오버로드는 RefreshToken이 없으므로 세 번째 인자는 null이다.
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, null, KEYCLOAK_SID);
            }
        }

        @Test
        void 기존_세션의_Principal이_다르면_isDifferentUserReLogin을_경유해_세션을_무효화하고_새_세션을_생성한다() {
            // Given — H-3/H-C: 재로그인 잔여물 방지 판별/무효화는 KeycloakSessionManager로 위임된다.
            when(request.getSession(false)).thenReturn(existingSession);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));
            when(sessionManager.isDifferentUserReLogin(existingSession, USER_SUB)).thenReturn(true);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                verify(sessionManager).isDifferentUserReLogin(existingSession, USER_SUB);
                verify(sessionManager).invalidateSession(existingSession);
                // 다른 사용자 재로그인 경로에서는 changeSessionId()로 회전하지 않는다 — 이전 세션을
                // 완전히 무효화하고 request.getSession(true)로 새 세션을 만든다.
                verify(request, never()).changeSessionId();
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, null, KEYCLOAK_SID);
            }
        }
    }

    @Nested
    class RefreshToken_선택 {

        @Test
        void RefreshToken이_없으면_세션에_저장하지_않는다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                // syncReLoginArtifacts에 refreshToken 자리에 null이 전달된다 — 세션에 저장하지 않는다는
                // 의도는 KeycloakSessionManager#syncReLoginArtifacts 내부에서 명시적 제거로 처리된다
                // (KeycloakSessionManagerTest에서 검증).
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, null, KEYCLOAK_SID);
            }
        }
    }

    @Nested
    class sid_클레임_없음 {

        @Test
        void ID_Token에_sid_클레임이_없으면_KeycloakSessionId_저장을_스킵한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(false));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response, KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE));

                // sid 클레임이 없으므로 syncReLoginArtifacts에 keycloakSid 자리에 null이 전달된다.
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, null, null);
            }
        }
    }

    @Nested
    class 오버로드_동작_동일 {

        @Test
        void ID_AccessToken_2개_인자_오버로드는_RefreshToken_없이_동작한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                Authentication result = loginService.authenticate(
                    request, response, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);

                assertThat(result).isNotNull();
                verify(authenticationProvider).createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);
                verify(sessionManager, never()).saveRefreshToken(any(), anyString());
                verify(securityContextRepository).saveContext(any(), eq(request), eq(response));
            }
        }

        @Test
        void ID_Access_RefreshToken_3개_인자_오버로드는_RefreshToken을_세션에_저장한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                Authentication result = loginService.authenticate(
                    request, response, ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE);

                assertThat(result).isNotNull();
                verify(authenticationProvider).createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);
            }
        }

        @Test
        void KeycloakTokens_오버로드와_동일하게_검증을_경유한다() {
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(newSession);
            when(authenticationProvider.createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE))
                .thenReturn(createSuccessfulAuthentication(true));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                loginService.authenticate(request, response,
                    KeycloakTokens.of(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE));

                verify(authenticationProvider).createAuthenticatedToken(ID_TOKEN_VALUE, ACCESS_TOKEN_VALUE);
                verify(sessionManager).syncReLoginArtifacts(newSession, USER_SUB, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);
            }
        }
    }
}
