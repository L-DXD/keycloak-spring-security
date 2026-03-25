package com.ids.keycloak.security.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.dto.LogoutRequest;
import com.ids.keycloak.security.dto.RefreshRequest;
import com.ids.keycloak.security.dto.TokenErrorResponse;
import com.ids.keycloak.security.dto.TokenRequest;
import com.ids.keycloak.security.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.lang.reflect.Field;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * {@link KeycloakTokenController} 단위 테스트.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakTokenControllerTest {

    private KeycloakTokenController controller;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private HttpServletRequest httpServletRequest;

    private static final String TOKEN_ENDPOINT = "https://keycloak.example.com/realms/test/protocol/openid-connect/token";
    private static final String LOGOUT_ENDPOINT = "https://keycloak.example.com/realms/test/protocol/openid-connect/logout";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String PREFIX = "/auth";

    @BeforeEach
    void setUp() throws Exception {
        controller = new KeycloakTokenController(
            TOKEN_ENDPOINT, LOGOUT_ENDPOINT, CLIENT_ID, CLIENT_SECRET, PREFIX
        );
        // Mock RestTemplate 주입 (리플렉션)
        Field restTemplateField = KeycloakTokenController.class.getDeclaredField("restTemplate");
        restTemplateField.setAccessible(true);
        restTemplateField.set(controller, restTemplate);
    }

    @Nested
    class 토큰_발급_테스트 {

        @Test
        @SuppressWarnings("unchecked")
        void 유효한_자격증명으로_토큰_발급에_성공한다() {
            // 준비
            Map<String, Object> responseBody = Map.of(
                "access_token", "new-access-token",
                "refresh_token", "new-refresh-token",
                "token_type", "Bearer",
                "expires_in", 300,
                "refresh_expires_in", 1800
            );
            when(restTemplate.postForEntity(eq(TOKEN_ENDPOINT), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

            TokenRequest request = new TokenRequest("testuser", "testpass");

            // 실행
            ResponseEntity<?> result = controller.issueToken(request, httpServletRequest);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(result.getBody()).isInstanceOf(TokenResponse.class);
            TokenResponse tokenResponse = (TokenResponse) result.getBody();
            assertThat(tokenResponse.getAccessToken()).isEqualTo("new-access-token");
            assertThat(tokenResponse.getRefreshToken()).isEqualTo("new-refresh-token");
            assertThat(tokenResponse.getTokenType()).isEqualTo("Bearer");
            assertThat(tokenResponse.getExpiresIn()).isEqualTo(300);
        }

        @Test
        @SuppressWarnings("unchecked")
        void 잘못된_자격증명이면_401을_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(TOKEN_ENDPOINT), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));

            TokenRequest request = new TokenRequest("wrong", "wrong");

            // 실행
            ResponseEntity<?> result = controller.issueToken(request, httpServletRequest);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(result.getBody()).isInstanceOf(TokenErrorResponse.class);
        }

        @Test
        @SuppressWarnings("unchecked")
        void Keycloak_통신_실패시_500을_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(TOKEN_ENDPOINT), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new RestClientException("Connection refused"));

            TokenRequest request = new TokenRequest("testuser", "testpass");

            // 실행
            ResponseEntity<?> result = controller.issueToken(request, httpServletRequest);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(result.getBody()).isInstanceOf(TokenErrorResponse.class);
            TokenErrorResponse error = (TokenErrorResponse) result.getBody();
            assertThat(error.getError()).isEqualTo("server_error");
        }
    }

    @Nested
    class 토큰_갱신_테스트 {

        @Test
        @SuppressWarnings("unchecked")
        void 유효한_refresh_token으로_토큰_갱신에_성공한다() {
            // 준비
            Map<String, Object> responseBody = Map.of(
                "access_token", "new-access-token-2",
                "refresh_token", "new-refresh-token-2",
                "token_type", "Bearer",
                "expires_in", 300,
                "refresh_expires_in", 1800
            );
            when(restTemplate.postForEntity(eq(TOKEN_ENDPOINT), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

            RefreshRequest request = new RefreshRequest("old-refresh-token");

            // 실행
            ResponseEntity<?> result = controller.refreshToken(request);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
            TokenResponse tokenResponse = (TokenResponse) result.getBody();
            assertThat(tokenResponse.getAccessToken()).isEqualTo("new-access-token-2");
        }

        @Test
        @SuppressWarnings("unchecked")
        void 만료된_refresh_token이면_401을_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(TOKEN_ENDPOINT), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));

            RefreshRequest request = new RefreshRequest("expired-refresh-token");

            // 실행
            ResponseEntity<?> result = controller.refreshToken(request);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Nested
    class 로그아웃_테스트 {

        @Test
        void 로그아웃에_성공하면_204를_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(LOGOUT_ENDPOINT), any(HttpEntity.class), eq(Void.class)))
                .thenReturn(ResponseEntity.noContent().build());

            LogoutRequest request = new LogoutRequest("valid-refresh-token");

            // 실행
            ResponseEntity<?> result = controller.logout(request);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            assertThat(result.getBody()).isNull();
        }

        @Test
        void 로그아웃_실패시_에러_응답을_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(LOGOUT_ENDPOINT), any(HttpEntity.class), eq(Void.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));

            LogoutRequest request = new LogoutRequest("invalid-refresh-token");

            // 실행
            ResponseEntity<?> result = controller.logout(request);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        void Keycloak_통신_실패시_500을_반환한다() {
            // 준비
            when(restTemplate.postForEntity(eq(LOGOUT_ENDPOINT), any(HttpEntity.class), eq(Void.class)))
                .thenThrow(new RestClientException("Connection refused"));

            LogoutRequest request = new LogoutRequest("valid-refresh-token");

            // 실행
            ResponseEntity<?> result = controller.logout(request);

            // 검증
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            TokenErrorResponse error = (TokenErrorResponse) result.getBody();
            assertThat(error.getError()).isEqualTo("server_error");
        }
    }
}
