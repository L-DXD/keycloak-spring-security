package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakSecurityConstants;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * {@link KeycloakAuthenticationProvider} 테스트.
 * Provider는 온라인 검증만 담당하고, 토큰 재발급은 Filter에서 처리합니다.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationProviderTest {

    @InjectMocks
    private KeycloakAuthenticationProvider provider;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    private static final String CLIENT_ID = "test-client-id";
    private static final String REGISTRATION_ID = KeycloakSecurityConstants.REGISTRATION_ID;
    private static final String USER_SUB = "user-123";

    @BeforeEach
    void setUp() {
    }

    private ClientRegistration createMockClientRegistration(String clientId) {
        return ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientId(clientId)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://auth-server/auth")
                .tokenUri("https://auth-server/token")
                .build();
    }

    private KeycloakPrincipal createPreAuthPrincipal(String subject) {
        return new KeycloakPrincipal(subject, Collections.emptyList(), Collections.emptyMap());
    }

    @Nested
    class 인증_성공_테스트 {

        @Test
        void 온라인_검증_성공시_인증에_성공하고_Principal을_생성한다() {
            // 1. 준비 - mock 객체를 mockStatic 이전에 생성
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                createPreAuthPrincipal(USER_SUB), idTokenVal, accessTokenVal, false
            );

            // Mock introspect response (mockStatic 밖에서 생성)
            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(true);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> introspectResponse = mock(KeycloakResponse.class);
            lenient().when(introspectResponse.getStatus()).thenReturn(200);
            lenient().when(introspectResponse.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(idTokenVal))
                .thenReturn(introspectResponse);

            // Mocking ClientRegistration
            when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                .thenReturn(createMockClientRegistration(CLIENT_ID));

            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // Mock JwtUtil - 클레임 파싱
                jwtUtilMock.when(() -> JwtUtil.parseClaimsWithoutValidation(idTokenVal))
                    .thenReturn(Map.of("sub", USER_SUB));
                jwtUtilMock.when(() -> JwtUtil.parseClaimsWithoutValidation(accessTokenVal))
                    .thenReturn(Map.of("sub", USER_SUB));
                jwtUtilMock.when(() -> JwtUtil.parseSubjectWithoutValidation(idTokenVal))
                    .thenReturn(USER_SUB);
                jwtUtilMock.when(() -> JwtUtil.extractRoles(any(), anyString()))
                    .thenReturn(List.of("user"));

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
        void ClientRegistration을_찾을_수_없으면_ConfigurationException이_발생한다() {
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

            // ClientRegistration null 반환
            when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(null);

            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // Mock JwtUtil
                jwtUtilMock.when(() -> JwtUtil.parseClaimsWithoutValidation(anyString()))
                    .thenReturn(Collections.emptyMap());
                jwtUtilMock.when(() -> JwtUtil.parseSubjectWithoutValidation(anyString()))
                    .thenReturn(USER_SUB);

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("clientRegistration");
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
