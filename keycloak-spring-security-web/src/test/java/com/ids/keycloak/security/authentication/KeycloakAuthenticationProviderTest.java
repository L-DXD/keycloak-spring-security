package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakSecurityConstants;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.exception.TokenExpiredException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.model.PreAuthenticationPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.client.RestClientException;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationProviderTest {

    @InjectMocks
    private KeycloakAuthenticationProvider provider;

    @Mock
    private JwtDecoder jwtDecoder;

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

    private Jwt createMockJwt(String tokenValue, String subject, Map<String, Object> claims) {
        return Jwt.withTokenValue(tokenValue)
                .header("alg", "RS256")
                .subject(subject)
                .claims(c -> c.putAll(claims))
                .build();
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

    private KeycloakResponse<KeycloakIntrospectResponse> createIntrospectResponse(int status) {
        return KeycloakResponse.<KeycloakIntrospectResponse>builder()
                .status(status)
                .body(new KeycloakIntrospectResponse())
                .build();
    }

    private KeycloakResponse<KeycloakTokenInfo> createTokenResponse(int status, KeycloakTokenInfo tokenInfo) {
        return KeycloakResponse.<KeycloakTokenInfo>builder()
                .status(status)
                .body(tokenInfo)
                .build();
    }

    @Nested
    class 인증_성공_테스트 {

        @Test
        void ID_토큰이_유효하면_인증에_성공하고_Principal을_생성한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String idTokenVal = "valid.id.token";
                String accessTokenVal = "valid.access.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
                );

                // Mock JwtUtil.isTokenExpired - 만료되지 않음
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(false);
                jwtUtilMock.when(() -> JwtUtil.extractRoles(any(), anyString()))
                    .thenReturn(List.of("user"));

                // Mocking JWTs
                Map<String, Object> accessClaims = new HashMap<>();
                accessClaims.put("sub", USER_SUB);
                accessClaims.put("resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("user"))));

                Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
                Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, accessClaims);

                when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
                when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

                // Mock 온라인 검증 - 성공 (200)
                when(keycloakClient.auth().authenticationByIntrospect(accessTokenVal))
                    .thenReturn(createIntrospectResponse(200));

                // Mocking ClientRegistration
                when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                    .thenReturn(createMockClientRegistration(CLIENT_ID));

                // 2. 실행
                Authentication result = provider.authenticate(authRequest);

                // 3. 검증
                assertThat(result).isInstanceOf(KeycloakAuthentication.class);
                assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);

                KeycloakPrincipal principal = (KeycloakPrincipal) result.getPrincipal();
                assertThat(principal.getName()).isEqualTo(USER_SUB);
            }
        }

        @Test
        void 토큰_만료시_Refresh_Token으로_재발급_성공하면_인증에_성공한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String oldIdToken = "old.id.token";
                String oldAccessToken = "old.access.token";
                String refreshToken = "valid.refresh.token";

                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal(USER_SUB), oldIdToken, oldAccessToken
                );
                authRequest.setDetails(refreshToken);

                // Mock JwtUtil.isTokenExpired - 만료됨
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(oldIdToken)).thenReturn(true);
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(oldAccessToken)).thenReturn(false);

                // 새 토큰
                String newIdTokenVal = "new.id.token";
                String newAccessTokenVal = "new.access.token";
                String newRefreshTokenVal = "new.refresh.token";

                // 새 토큰은 만료되지 않음
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(newIdTokenVal)).thenReturn(false);
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(newAccessTokenVal)).thenReturn(false);
                jwtUtilMock.when(() -> JwtUtil.extractRoles(any(), anyString()))
                    .thenReturn(List.of("admin"));

                Jwt newIdTokenJwt = createMockJwt(newIdTokenVal, USER_SUB, Collections.emptyMap());
                Map<String, Object> accessClaims = new HashMap<>();
                accessClaims.put("sub", USER_SUB);
                accessClaims.put("resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("admin"))));
                Jwt newAccessTokenJwt = createMockJwt(newAccessTokenVal, USER_SUB, accessClaims);

                when(jwtDecoder.decode(newIdTokenVal)).thenReturn(newIdTokenJwt);
                when(jwtDecoder.decode(newAccessTokenVal)).thenReturn(newAccessTokenJwt);

                // Mock 토큰 재발급
                KeycloakTokenInfo newTokenInfo = KeycloakTokenInfo.builder()
                    .idToken(newIdTokenVal)
                    .accessToken(newAccessTokenVal)
                    .refreshToken(newRefreshTokenVal)
                    .build();

                when(keycloakClient.auth().reissueToken(refreshToken))
                    .thenReturn(createTokenResponse(200, newTokenInfo));

                // Mock ClientRegistration
                when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                    .thenReturn(createMockClientRegistration(CLIENT_ID));

                // 2. 실행
                Authentication result = provider.authenticate(authRequest);

                // 3. 검증
                assertThat(result.getDetails()).isInstanceOf(KeycloakTokenInfo.class);
                KeycloakTokenInfo resultTokens = (KeycloakTokenInfo) result.getDetails();
                assertThat(resultTokens.getRefreshToken()).isEqualTo(newRefreshTokenVal);
            }
        }
    }

    @Nested
    class 인증_실패_테스트 {

        @Test
        void Refresh_Token이_없는데_토큰이_만료되면_RefreshTokenException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String idToken = "expired.id.token";
                String accessToken = "expired.access.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal("anon"), idToken, accessToken
                );
                // No details set (null) - Refresh Token 없음

                // Mock JwtUtil.isTokenExpired - 만료됨
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(idToken)).thenReturn(true);

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(RefreshTokenException.class)
                    .hasMessageContaining("Refresh Token 정보가 없습니다");
            }
        }

        @Test
        void 토큰_서명_검증_실패시_AuthenticationFailedException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String idToken = "invalid.signature.token";
                String accessToken = "access.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal("anon"), idToken, accessToken
                );

                // Mock JwtUtil.isTokenExpired - 만료되지 않음
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(false);

                // JwtDecoder가 서명 검증 실패
                when(jwtDecoder.decode(idToken)).thenThrow(new JwtException("Invalid signature"));

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(AuthenticationFailedException.class)
                    .hasMessageContaining("토큰 검증 실패");
            }
        }
    }

    @Nested
    class 예외_테스트 {

        @Test
        void Refresh_Token_재발급_중_통신_오류시_ConfigurationException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String refreshToken = "valid.refresh.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal("anon"), "expired.token", "access.token"
                );
                authRequest.setDetails(refreshToken);

                // Mock JwtUtil.isTokenExpired - 만료됨
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(true);

                // 통신 오류
                when(keycloakClient.auth().reissueToken(refreshToken))
                    .thenThrow(new RestClientException("Connection refused"));

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("통신할 수 없습니다");
            }
        }

        @Test
        void Refresh_Token_재발급_401_응답시_RefreshTokenException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String refreshToken = "expired.refresh.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal("anon"), "expired.token", "access.token"
                );
                authRequest.setDetails(refreshToken);

                // Mock JwtUtil.isTokenExpired - 만료됨
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(true);

                // 401 응답
                when(keycloakClient.auth().reissueToken(refreshToken))
                    .thenReturn(createTokenResponse(401, null));

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(RefreshTokenException.class)
                    .hasMessageContaining("만료되었거나 유효하지 않습니다");
            }
        }

        @Test
        void ClientRegistration을_찾을_수_없으면_ConfigurationException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String idTokenVal = "valid.id.token";
                String accessTokenVal = "valid.access.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
                );

                // Mock JwtUtil.isTokenExpired - 만료되지 않음
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(false);

                Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
                Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, Collections.emptyMap());

                when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
                when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

                // Mock 온라인 검증 - 성공
                when(keycloakClient.auth().authenticationByIntrospect(accessTokenVal))
                    .thenReturn(createIntrospectResponse(200));

                // ClientRegistration null 반환
                when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(null);

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("clientRegistration");
            }
        }

        @Test
        void 온라인_검증_500_응답시_ConfigurationException이_발생한다() {
            try (MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {
                // 1. 준비
                String idTokenVal = "valid.id.token";
                String accessTokenVal = "valid.access.token";
                KeycloakAuthentication authRequest = new KeycloakAuthentication(
                    new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
                );

                // Mock JwtUtil.isTokenExpired - 만료되지 않음
                jwtUtilMock.when(() -> JwtUtil.isTokenExpired(anyString())).thenReturn(false);

                Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
                Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, Collections.emptyMap());

                when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
                when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

                // Mock 온라인 검증 - 서버 오류 (500)
                when(keycloakClient.auth().authenticationByIntrospect(accessTokenVal))
                    .thenReturn(createIntrospectResponse(500));

                // 2. 실행 & 검증
                assertThatThrownBy(() -> provider.authenticate(authRequest))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("Keycloak 서버");
            }
        }
    }
}
