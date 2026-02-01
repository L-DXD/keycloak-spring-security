package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

/**
 * {@link KeycloakAuthenticationProvider} 테스트.
 * Provider는 온라인 검증만 담당하고, 토큰 재발급은 Filter에서 처리합니다.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationProviderTest {

    private KeycloakAuthenticationProvider provider;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    private static final String CLIENT_ID = "test-client-id";
    private static final String USER_SUB = "user-123";

    @BeforeEach
    void setUp() {
        provider = new KeycloakAuthenticationProvider(keycloakClient, CLIENT_ID);
    }

    private KeycloakPrincipal createPreAuthPrincipal(String subject) {
        OidcIdToken idToken = new OidcIdToken(
            "token-value",
            Instant.now(),
            Instant.now().plusSeconds(3600),
            Map.of("sub", subject)
        );
        return new KeycloakPrincipal(subject, Collections.emptyList(), idToken, null);
    }

    @Nested
    class 인증_성공_테스트 {

        @Test
        void 온라인_검증_성공시_인증에_성공하고_Principal을_생성한다() {
            // 1. 준비
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response
            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // Mock UserInfo response
            KeycloakUserInfo keycloakUserInfo = mock(KeycloakUserInfo.class);
            lenient().when(keycloakUserInfo.getSubject()).thenReturn(USER_SUB);
            lenient().when(keycloakUserInfo.getOtherInfo()).thenReturn(new HashMap<>());

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(200);
            lenient().when(userInfoResponse.getBody()).thenReturn(Optional.of(keycloakUserInfo));

            when(keycloakClient.user().getUserInfo(accessTokenVal))
                .thenReturn(userInfoResponse);

            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // Mock JwtUtil - 클레임 파싱
                Map<String, Object> claims = new HashMap<>();
                claims.put("sub", USER_SUB);
                claims.put("iat", Instant.now().getEpochSecond());
                claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

                jwtUtilMock.when(() -> JwtUtil.parseClaimsWithoutValidation(idTokenVal))
                    .thenReturn(claims);
                jwtUtilMock.when(() -> JwtUtil.parseSubjectWithoutValidation(idTokenVal))
                    .thenReturn(USER_SUB);

                // 2. 실행
                Authentication result = provider.authenticate(authRequest);

                // 3. 검증
                assertThat(result).isInstanceOf(KeycloakAuthentication.class);
                assertThat(result.isAuthenticated()).isTrue();
                assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);

                KeycloakPrincipal principal = (KeycloakPrincipal) result.getPrincipal();
                assertThat(principal.getName()).isEqualTo(USER_SUB);
            }
        }
    }

    @Nested
    class 인증_실패_테스트 {

        @Test
        void 온라인_검증_active_false시_IntrospectionFailedException이_발생한다() {
            // 1. 준비
            String idTokenVal = "invalid.id.token";
            String accessTokenVal = "invalid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response - active=false
            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(false);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // 2. 실행 & 검증
            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(IntrospectionFailedException.class)
                .hasMessageContaining("유효하지 않습니다");
        }

        @Test
        void 온라인_검증_401_응답시_IntrospectionFailedException이_발생한다() {
            // 1. 준비
            String idTokenVal = "expired.id.token";
            String accessTokenVal = "expired.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response - 401
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(401);

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // 2. 실행 & 검증
            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(IntrospectionFailedException.class);
        }
    }

    @Nested
    class 예외_테스트 {

        @Test
        void UserInfo_조회_401_응답시_UserInfoFetchException이_발생한다() {
            // 1. 준비
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response - success
            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // Mock UserInfo response - 401
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);

            when(keycloakClient.user().getUserInfo(accessTokenVal))
                .thenReturn(userInfoResponse);

            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                Map<String, Object> claims = new HashMap<>();
                claims.put("sub", USER_SUB);
                claims.put("iat", Instant.now().getEpochSecond());
                claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

                jwtUtilMock.when(() -> JwtUtil.parseClaimsWithoutValidation(idTokenVal))
                    .thenReturn(claims);
                jwtUtilMock.when(() -> JwtUtil.parseSubjectWithoutValidation(idTokenVal))
                    .thenReturn(USER_SUB);

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(UserInfoFetchException.class)
                    .hasMessageContaining("401");
            }
        }

        @Test
        void 온라인_검증_500_응답시_ConfigurationException이_발생한다() {
            // 1. 준비
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response - 500
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(500);

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // 2. 실행 & 검증
            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Keycloak 서버");
        }
    }
}
