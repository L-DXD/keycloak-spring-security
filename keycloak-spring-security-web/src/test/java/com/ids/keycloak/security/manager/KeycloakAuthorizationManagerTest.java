package com.ids.keycloak.security.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.client.RestClientException;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthorizationManagerTest {

    private KeycloakAuthorizationManager manager;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    private static final String ACCESS_TOKEN = "test-access-token";
    private static final String REQUEST_URI = "/api/test";
    private static final String REQUEST_METHOD = "GET";

    @BeforeEach
    void setUp() {
        manager = new KeycloakAuthorizationManager(keycloakClient);
    }

    private RequestAuthorizationContext mockContext() {
        RequestAuthorizationContext context = mock(RequestAuthorizationContext.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(context.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(REQUEST_METHOD);
        when(request.getRequestURI()).thenReturn(REQUEST_URI);
        return context;
    }

    @SuppressWarnings("unchecked")
    private KeycloakResponse<KeycloakAuthorizationResult> mockGrantedResponse(boolean granted) {
        KeycloakResponse<KeycloakAuthorizationResult> response = mock(KeycloakResponse.class);
        KeycloakAuthorizationResult authResult = mock(KeycloakAuthorizationResult.class);
        when(response.getBody()).thenReturn(Optional.of(authResult));
        when(authResult.isGranted()).thenReturn(granted);
        return response;
    }

    @Nested
    class KeycloakAuthentication_인가_테스트 {

        @Test
        void 인가_성공시_AuthorizationDecision이_true를_반환한다() {
            // 준비
            KeycloakAuthentication auth = mock(KeycloakAuthentication.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getAccessToken()).thenReturn(ACCESS_TOKEN);

            KeycloakResponse<KeycloakAuthorizationResult> response = mockGrantedResponse(true);
            when(keycloakClient.auth().authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
                .thenReturn(response);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isTrue();
            verify(keycloakClient.auth()).authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD);
        }

        @Test
        void 인가_거부시_AuthorizationDecision이_false를_반환한다() {
            // 준비
            KeycloakAuthentication auth = mock(KeycloakAuthentication.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getAccessToken()).thenReturn(ACCESS_TOKEN);

            KeycloakResponse<KeycloakAuthorizationResult> response = mockGrantedResponse(false);
            when(keycloakClient.auth().authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
                .thenReturn(response);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isFalse();
        }
    }

    @Nested
    class BasicAuthenticationToken_인가_테스트 {

        @Test
        void AccessTokenHolder_분기를_통해_인가_성공시_AuthorizationDecision이_true를_반환한다() {
            // 준비
            BasicAuthenticationToken auth = mock(BasicAuthenticationToken.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getAccessToken()).thenReturn(ACCESS_TOKEN);

            KeycloakResponse<KeycloakAuthorizationResult> response = mockGrantedResponse(true);
            when(keycloakClient.auth().authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
                .thenReturn(response);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isTrue();
            verify(keycloakClient.auth()).authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD);
        }
    }

    @Nested
    class BearerTokenAuthentication_인가_테스트 {

        @Test
        void Bearer_토큰으로_인가_성공시_AuthorizationDecision이_true를_반환한다() {
            // 준비
            BearerTokenAuthentication auth = mock(BearerTokenAuthentication.class);
            OAuth2AccessToken oauthToken = mock(OAuth2AccessToken.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getToken()).thenReturn(oauthToken);
            when(oauthToken.getTokenValue()).thenReturn("bearer-token");

            KeycloakResponse<KeycloakAuthorizationResult> response = mockGrantedResponse(true);
            when(keycloakClient.auth().authorization("bearer-token", REQUEST_URI, REQUEST_METHOD))
                .thenReturn(response);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isTrue();
            verify(keycloakClient.auth()).authorization("bearer-token", REQUEST_URI, REQUEST_METHOD);
        }
    }

    @Nested
    class 미인증_사용자_테스트 {

        @Test
        void 미인증_사용자는_AuthorizationDecision이_false를_반환하고_Keycloak을_호출하지_않는다() {
            // 준비
            KeycloakAuthentication auth = mock(KeycloakAuthentication.class);
            when(auth.isAuthenticated()).thenReturn(false);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isFalse();
            verify(keycloakClient.auth(), never()).authorization(any(), any(), any());
        }
    }

    @Nested
    class 미지원_인증타입_테스트 {

        @Test
        void UsernamePasswordAuthenticationToken은_AuthorizationDecision이_false를_반환하고_Keycloak을_호출하지_않는다() {
            // 준비
            UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("user", "password", Collections.emptyList());

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isFalse();
            verify(keycloakClient.auth(), never()).authorization(any(), any(), any());
        }
    }

    @Nested
    class Keycloak_통신_오류_테스트 {

        @Test
        void Keycloak_통신_오류시_AuthorizationDecision이_false를_반환한다() {
            // 준비
            KeycloakAuthentication auth = mock(KeycloakAuthentication.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getAccessToken()).thenReturn(ACCESS_TOKEN);

            when(keycloakClient.auth().authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
                .thenThrow(new RestClientException("Connection refused"));

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isFalse();
        }
    }

    @Nested
    class Keycloak_응답_없음_테스트 {

        @Test
        void Keycloak_응답_body가_없으면_AuthorizationDecision이_false를_반환한다() {
            // 준비
            KeycloakAuthentication auth = mock(KeycloakAuthentication.class);
            when(auth.isAuthenticated()).thenReturn(true);
            when(auth.getAccessToken()).thenReturn(ACCESS_TOKEN);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakAuthorizationResult> response = mock(KeycloakResponse.class);
            when(response.getBody()).thenReturn(Optional.empty());
            when(keycloakClient.auth().authorization(ACCESS_TOKEN, REQUEST_URI, REQUEST_METHOD))
                .thenReturn(response);

            RequestAuthorizationContext context = mockContext();
            Supplier<org.springframework.security.core.Authentication> supplier = () -> auth;

            // 실행
            AuthorizationDecision decision = manager.check(supplier, context);

            // 검증
            assertThat(decision.isGranted()).isFalse();
        }
    }
}
