package com.ids.keycloak.security.authentication;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.session.KeycloakSessionManager;
import com.ids.keycloak.security.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

@ExtendWith(MockitoExtension.class)
class OidcLoginSuccessHandlerTest {

    @Mock
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Mock
    private KeycloakSessionManager sessionManager;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private OAuth2AuthenticationToken oauthToken;

    @Mock
    private OidcUser oidcUser;

    @Mock
    private OidcIdToken idToken;

    @Mock
    private OAuth2AuthorizedClient authorizedClient;

    @Mock
    private OAuth2AccessToken accessToken;

    @Mock
    private OAuth2RefreshToken refreshToken;

    private OidcLoginSuccessHandler handler;

    private static final String PRINCIPAL_NAME = "user-123";
    private static final String KEYCLOAK_SID = "keycloak-sid-abc";
    private static final String REGISTRATION_ID = "keycloak";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";
    private static final String ID_TOKEN_VALUE = "id-token-value";
    private static final String REFRESH_TOKEN_VALUE = "refresh-token-value";
    private static final String DEFAULT_SUCCESS_URL = "/dashboard";

    @BeforeEach
    void setUp() {
        handler = new OidcLoginSuccessHandler(authorizedClientRepository, sessionManager, DEFAULT_SUCCESS_URL);
    }

    private ClientRegistration createClientRegistration() {
        return ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("test-client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://keycloak/auth")
            .tokenUri("https://keycloak/token")
            .build();
    }

    @Nested
    class 정상_케이스 {

        @Test
        void OIDC_로그인_성공_시_토큰을_쿠키에_저장하고_세션에_정보를_기록한다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(KEYCLOAK_SID);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(authorizedClient.getRefreshToken()).thenReturn(refreshToken);

            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));
            when(refreshToken.getTokenValue()).thenReturn(REFRESH_TOKEN_VALUE);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then — H-3/H-C: 개별 save* 호출이 아니라 KeycloakSessionManager로 추출된 공통
                // 헬퍼 syncReLoginArtifacts를 경유해 Principal Name/Refresh Token/Keycloak Session ID가
                // 함께 동기화된다(KeycloakLoginService#authenticate와 공유하는 로직).
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);

                cookieUtil.verify(() -> CookieUtil.addCookie(response, CookieUtil.ACCESS_TOKEN_NAME, ACCESS_TOKEN_VALUE, 300));
                cookieUtil.verify(() -> CookieUtil.addCookie(response, CookieUtil.ID_TOKEN_NAME, ID_TOKEN_VALUE, 300));
            }
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void OAuth2AuthenticationToken이_아닌_경우_토큰_처리를_건너뛴다() throws Exception {
            // Given
            Authentication genericAuth = org.mockito.Mockito.mock(Authentication.class);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When
                handler.onAuthenticationSuccess(request, response, genericAuth);

                // Then
                verify(sessionManager, never()).savePrincipalName(any(), anyString());
                verify(sessionManager, never()).saveKeycloakSessionId(any(), anyString());
                verify(sessionManager, never()).saveRefreshToken(any(), anyString());

                cookieUtil.verify(
                    () -> CookieUtil.addCookie(any(), anyString(), anyString(), anyInt()),
                    never()
                );
            }
        }

        @Test
        void 세션이_null이면_세션_저장은_스킵하고_쿠키만_생성한다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(null);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then
                verify(sessionManager, never()).savePrincipalName(any(), anyString());
                verify(sessionManager, never()).saveKeycloakSessionId(any(), anyString());
                verify(sessionManager, never()).saveRefreshToken(any(), anyString());

                cookieUtil.verify(() -> CookieUtil.addCookie(response, CookieUtil.ACCESS_TOKEN_NAME, ACCESS_TOKEN_VALUE, 300));
                cookieUtil.verify(() -> CookieUtil.addCookie(response, CookieUtil.ID_TOKEN_NAME, ID_TOKEN_VALUE, 300));
            }
        }

        @Test
        void AuthorizedClient가_null이면_Access_Token_쿠키를_생성하지_않는다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(KEYCLOAK_SID);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(null);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then — AuthorizedClient가 null이라 refreshTokenValue는 null로 syncReLoginArtifacts에
                // 전달된다(H-3/H-C 공통 헬퍼).
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, null, KEYCLOAK_SID);

                cookieUtil.verify(
                    () -> CookieUtil.addCookie(eq(response), eq(CookieUtil.ACCESS_TOKEN_NAME), anyString(), anyInt()),
                    never()
                );
                cookieUtil.verify(() -> CookieUtil.addCookie(response, CookieUtil.ID_TOKEN_NAME, ID_TOKEN_VALUE, 300));
            }
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void OidcUser에_sid_클레임이_없으면_Keycloak_Session_ID_저장을_스킵한다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(null);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then — sid 클레임이 없으므로 syncReLoginArtifacts에 keycloakSid 자리에 null이
                // 전달된다(H-3/H-C 공통 헬퍼). refreshToken도 이 테스트에서는 미제공이라 null이다.
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, null, null);
            }
        }

        @Test
        void RefreshToken이_null이면_세션에_저장하지_않는다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(KEYCLOAK_SID);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(authorizedClient.getRefreshToken()).thenReturn(null);

            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then — RefreshToken이 null이므로 syncReLoginArtifacts에도 null로 전달된다
                // (H-3/H-C 공통 헬퍼).
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, null, KEYCLOAK_SID);
            }
        }

        @Test
        void Principal이_OidcUser가_아니면_토큰_처리를_건너뛴다() throws Exception {
            // Given - OidcUser가 아닌 일반 OAuth2User 사용
            OAuth2User nonOidcPrincipal = org.mockito.Mockito.mock(OAuth2User.class);

            when(oauthToken.getPrincipal()).thenReturn(nonOidcPrincipal);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then - OidcUser가 아니면 early return하므로 아무 작업도 하지 않음
                verify(sessionManager, never()).savePrincipalName(any(), anyString());
                verify(sessionManager, never()).saveKeycloakSessionId(any(), anyString());
                verify(sessionManager, never()).saveRefreshToken(any(), anyString());

                cookieUtil.verify(
                    () -> CookieUtil.addCookie(any(), anyString(), anyString(), anyInt()),
                    never()
                );
            }
        }
    }

    @Nested
    class H_C_재로그인_잔여물_방지 {

        @Test
        void 기존_세션의_Principal이_다르면_isDifferentUserReLogin을_경유해_세션을_무효화하고_새_세션에_동기화한다() throws Exception {
            // Given — OAuth2LoginAuthenticationFilter가 이 핸들러를 호출하기 전에 이미
            // changeSessionId()로 세션 ID를 회전시키므로, 여기서는 그 changeSessionId()가 보존한
            // 이전 사용자 잔여물만 판별·정리한다(KeycloakLoginService#authenticate와 공유 로직).
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);
            when(request.getSession(true)).thenReturn(session);
            when(sessionManager.isDifferentUserReLogin(session, PRINCIPAL_NAME)).thenReturn(true);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(KEYCLOAK_SID);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(authorizedClient.getRefreshToken()).thenReturn(refreshToken);

            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));
            when(refreshToken.getTokenValue()).thenReturn(REFRESH_TOKEN_VALUE);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then
                verify(sessionManager).isDifferentUserReLogin(session, PRINCIPAL_NAME);
                verify(sessionManager).invalidateSession(session);
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);
            }
        }

        @Test
        void 기존_세션의_Principal이_같으면_무효화하지_않고_기존_세션에_그대로_동기화한다() throws Exception {
            // Given
            when(oauthToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(oauthToken.getPrincipal()).thenReturn(oidcUser);
            when(oauthToken.getAuthorizedClientRegistrationId()).thenReturn(REGISTRATION_ID);

            when(request.getSession(false)).thenReturn(session);
            when(sessionManager.isDifferentUserReLogin(session, PRINCIPAL_NAME)).thenReturn(false);

            when(oidcUser.getName()).thenReturn(PRINCIPAL_NAME);
            when(oidcUser.getAuthorities()).thenReturn(Collections.emptyList());
            when(oidcUser.getUserInfo()).thenReturn(null);
            when(oidcUser.getIdToken()).thenReturn(idToken);
            when(idToken.getClaimAsString("sid")).thenReturn(KEYCLOAK_SID);
            when(idToken.getTokenValue()).thenReturn(ID_TOKEN_VALUE);
            when(idToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

            when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), eq(request)))
                .thenReturn(authorizedClient);
            when(authorizedClient.getAccessToken()).thenReturn(accessToken);
            when(authorizedClient.getRefreshToken()).thenReturn(refreshToken);

            when(accessToken.getTokenValue()).thenReturn(ACCESS_TOKEN_VALUE);
            when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(300));
            when(refreshToken.getTokenValue()).thenReturn(REFRESH_TOKEN_VALUE);

            try (MockedStatic<CookieUtil> cookieUtil = mockStatic(CookieUtil.class)) {
                cookieUtil.when(() -> CookieUtil.calculateRestMaxAge(any(Instant.class))).thenReturn(300);

                // When
                handler.onAuthenticationSuccess(request, response, oauthToken);

                // Then
                verify(sessionManager, never()).invalidateSession(any());
                verify(request, never()).getSession(true);
                verify(sessionManager).syncReLoginArtifacts(session, PRINCIPAL_NAME, REFRESH_TOKEN_VALUE, KEYCLOAK_SID);
            }
        }
    }

    @Nested
    class DefaultSuccessUrl_설정 {

        private String getDefaultTargetUrl(OidcLoginSuccessHandler handler) throws Exception {
            // OidcLoginSuccessHandler → SavedRequestAwareAuthenticationSuccessHandler
            // → SimpleUrlAuthenticationSuccessHandler → AbstractAuthenticationTargetUrlRequestHandler
            Class<?> clazz = handler.getClass();
            while (clazz != null) {
                try {
                    java.lang.reflect.Field field = clazz.getDeclaredField("defaultTargetUrl");
                    field.setAccessible(true);
                    return (String) field.get(handler);
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            throw new NoSuchFieldException("defaultTargetUrl");
        }

        @Test
        void 생성자에서_전달된_defaultSuccessUrl이_설정된다() throws Exception {
            // Given
            String customUrl = "/custom-home";

            // When
            OidcLoginSuccessHandler customHandler = new OidcLoginSuccessHandler(
                authorizedClientRepository, sessionManager, customUrl);

            // Then
            assert customUrl.equals(getDefaultTargetUrl(customHandler));
        }

        @Test
        void 기본값_슬래시가_설정되면_루트로_리다이렉트된다() throws Exception {
            // Given
            String rootUrl = "/";

            // When
            OidcLoginSuccessHandler rootHandler = new OidcLoginSuccessHandler(
                authorizedClientRepository, sessionManager, rootUrl);

            // Then
            assert "/".equals(getDefaultTargetUrl(rootHandler));
        }
    }
}
