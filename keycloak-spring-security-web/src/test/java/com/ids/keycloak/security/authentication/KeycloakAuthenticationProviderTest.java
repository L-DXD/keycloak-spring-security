package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakSecurityConstants;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.model.PreAuthenticationPrincipal;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.Collections;
import java.util.HashMap;
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
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
    // Using constant from the actual class to ensure matching
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

    @Nested
    class 인증_성공_테스트 {

        @Test
        void ID_토큰이_유효하면_인증에_성공하고_Principal을_생성한다() {
            // 1. 준비
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
            );

            // Mocking JWTs
            Map<String, Object> accessClaims = new HashMap<>();
            accessClaims.put("sub", USER_SUB);
            // resource_access: { "test-client-id": { "roles": ["user"] } }
            accessClaims.put("resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("user"))));

            Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
            Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, accessClaims);

            when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
            when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

            // Mocking ClientRegistration
            when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                .thenReturn(createMockClientRegistration(CLIENT_ID));

            // 5. 실행
            Authentication result = provider.authenticate(authRequest);

            // 6. 검증
            assertThat(result).isInstanceOf(KeycloakAuthentication.class);
            assertThat(result.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
            
            KeycloakPrincipal principal = (KeycloakPrincipal) result.getPrincipal();
            assertThat(principal.getName()).isEqualTo(USER_SUB);
            assertThat(principal.getAuthorities())
                .extracting(org.springframework.security.core.GrantedAuthority::getAuthority)
                .contains("ROLE_user"); 

            verify(keycloakClient.auth()).authenticationByIntrospect(idTokenVal);
        }

        @Test
        void ID_토큰이_유효하고_Refresh_Token이_없어도_인증에_성공한다() {
            // 1. 준비
            String idTokenVal = "valid.id.token";
            String accessTokenVal = "valid.access.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
            );
            // Refresh Token 미설정 (null)

            // Mocking JWTs
            Map<String, Object> accessClaims = new HashMap<>();
            accessClaims.put("sub", USER_SUB);
            accessClaims.put("resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("user"))));

            Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
            Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, accessClaims);

            when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
            when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

            // Mocking ClientRegistration
            when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                .thenReturn(createMockClientRegistration(CLIENT_ID));

            // 2. 실행
            Authentication result = provider.authenticate(authRequest);

            // 3. 검증
            assertThat(result.isAuthenticated()).isTrue();
            verify(keycloakClient.auth()).authenticationByIntrospect(idTokenVal);
            verify(keycloakClient.auth(), never()).reissueToken(anyString());
        }

        @Test
        void ID_토큰_검증_실패시_Refresh_Token으로_재발급_성공하면_인증에_성공한다() {
            // 1. 준비
            String oldIdToken = "old.id.token";
            String oldAccessToken = "old.access.token";
            String refreshToken = "valid.refresh.token";
            
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                new PreAuthenticationPrincipal(USER_SUB), oldIdToken, oldAccessToken
            );
            authRequest.setDetails(refreshToken); // Set refresh token in details

            // 2. Mock JwtDecoder: First fail, then success
            when(jwtDecoder.decode(oldIdToken)).thenThrow(new JwtException("Expired"));

            String newIdTokenVal = "new.id.token";
            String newAccessTokenVal = "new.access.token";
            String newRefreshTokenVal = "new.refresh.token";

            Jwt newIdTokenJwt = createMockJwt(newIdTokenVal, USER_SUB, Collections.emptyMap());
            
            Map<String, Object> accessClaims = new HashMap<>();
            accessClaims.put("sub", USER_SUB);
            accessClaims.put("resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("admin"))));
            Jwt newAccessTokenJwt = createMockJwt(newAccessTokenVal, USER_SUB, accessClaims);

            when(jwtDecoder.decode(newIdTokenVal)).thenReturn(newIdTokenJwt);
            when(jwtDecoder.decode(newAccessTokenVal)).thenReturn(newAccessTokenJwt);

            // 3. Mock KeycloakClient: reissue
            KeycloakTokenInfo newTokenInfo = KeycloakTokenInfo.builder()
                .idToken(newIdTokenVal)
                .accessToken(newAccessTokenVal)
                .refreshToken(newRefreshTokenVal)
                .build();
            
            when(keycloakClient.auth().reissueToken(refreshToken).getBody())
                .thenReturn(Optional.of(newTokenInfo));

            // Mock ClientRegistration
            when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
                .thenReturn(createMockClientRegistration(CLIENT_ID));

            // 4. 실행
            Authentication result = provider.authenticate(authRequest);

            // 5. 검증
            assertThat(result.getDetails()).isInstanceOf(KeycloakTokenInfo.class);
            KeycloakTokenInfo resultTokens = (KeycloakTokenInfo) result.getDetails();
            assertThat(resultTokens.getRefreshToken()).isEqualTo(newRefreshTokenVal);

            KeycloakPrincipal principal = (KeycloakPrincipal) result.getPrincipal();
            assertThat(principal.getAuthorities())
                .extracting(org.springframework.security.core.GrantedAuthority::getAuthority)
                .contains("ROLE_admin");
        }
    }

    @Nested
    class 인증_실패_테스트 {

        @Test
        void Refresh_Token이_없는데_ID_토큰도_유효하지_않으면_인증에_실패한다() {
            // 1. 준비
            String idToken = "invalid.id.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                new PreAuthenticationPrincipal("anon"), idToken, "access.token"
            );
            // No details set (null)

            when(jwtDecoder.decode(idToken)).thenThrow(new JwtException("Invalid token"));

            // 3. 실행 & 4. 검증
            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(RefreshTokenException.class)
                .hasMessageContaining("Refresh Token 정보가 없습니다");
        }
    }

    @Nested
    class 예외_테스트 {

        @Test
        void Refresh_Token_재발급_요청이_실패하면_AuthenticationFailedException이_발생한다() {
            // 1. 준비
            String refreshToken = "invalid.refresh.token";
            KeycloakAuthentication authRequest = new KeycloakAuthentication(
                new PreAuthenticationPrincipal("anon"), "expired.token", "access.token"
            );
            authRequest.setDetails(refreshToken);

            when(jwtDecoder.decode(anyString())).thenThrow(new JwtException("Expired"));
            
            when(keycloakClient.auth().reissueToken(refreshToken)).thenThrow(new RestClientException("Connection refused"));

            // 3. 실행 & 검증
            assertThatThrownBy(() -> provider.authenticate(authRequest))
                .isInstanceOf(AuthenticationFailedException.class);
        }
        
        @Test
        void ClientRegistration을_찾을_수_없으면_ConfigurationException이_발생한다() {
             // 1. 준비 (Valid tokens but no client config)
             String idTokenVal = "valid.id.token";
             String accessTokenVal = "valid.access.token";
             KeycloakAuthentication authRequest = new KeycloakAuthentication(
                 new PreAuthenticationPrincipal(USER_SUB), idTokenVal, accessTokenVal
             );

             Jwt idTokenJwt = createMockJwt(idTokenVal, USER_SUB, Collections.emptyMap());
             Jwt accessTokenJwt = createMockJwt(accessTokenVal, USER_SUB, Collections.emptyMap());

             when(jwtDecoder.decode(idTokenVal)).thenReturn(idTokenJwt);
             when(jwtDecoder.decode(accessTokenVal)).thenReturn(accessTokenJwt);

             // Mock Repo returning null
             when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).thenReturn(null);

             // 3. 실행 & 검증
             assertThatThrownBy(() -> provider.authenticate(authRequest))
                 .isInstanceOf(ConfigurationException.class);
        }
    }
}