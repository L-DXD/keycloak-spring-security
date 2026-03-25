package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.HashMap;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.web.client.RestClientException;

/**
 * {@link KeycloakOpaqueTokenIntrospector} 단위 테스트.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakOpaqueTokenIntrospectorTest {

    private KeycloakOpaqueTokenIntrospector introspector;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeycloakClient keycloakClient;

    private static final String CLIENT_ID = "test-client";
    private static final String USER_SUB = "user-123";
    private static final String ACCESS_TOKEN = "valid.access.token";

    @BeforeEach
    void setUp() {
        introspector = new KeycloakOpaqueTokenIntrospector(keycloakClient, CLIENT_ID);
    }

    @Nested
    class Introspect_성공_테스트 {

        @Test
        void active_true이면_KeycloakPrincipal을_반환한다() {
            // 준비: introspect 성공
            mockIntrospectSuccess();
            // 준비: UserInfo 성공
            mockUserInfoSuccess();

            // 실행
            OAuth2AuthenticatedPrincipal result = introspector.introspect(ACCESS_TOKEN);

            // 검증
            assertThat(result).isInstanceOf(KeycloakPrincipal.class);
            KeycloakPrincipal principal = (KeycloakPrincipal) result;
            assertThat(principal.getName()).isEqualTo(USER_SUB);
        }

        @Test
        void UserInfo_조회_실패해도_Principal은_생성된다() {
            // 준비: introspect 성공
            mockIntrospectSuccess();

            // 준비: UserInfo 실패 (401)
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakUserInfo> userInfoResponse = mock(KeycloakResponse.class);
            lenient().when(userInfoResponse.getStatus()).thenReturn(401);
            when(keycloakClient.user().getUserInfo(ACCESS_TOKEN)).thenReturn(userInfoResponse);

            // 실행
            OAuth2AuthenticatedPrincipal result = introspector.introspect(ACCESS_TOKEN);

            // 검증: UserInfo가 없어도 Principal은 생성됨 (subject는 "unknown")
            assertThat(result).isInstanceOf(KeycloakPrincipal.class);
        }
    }

    @Nested
    class Introspect_실패_테스트 {

        @Test
        void active_false이면_BadOpaqueTokenException이_발생한다() {
            // 준비: active=false
            KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
            lenient().when(introspectBody.getActive()).thenReturn(false);

            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> response = mock(KeycloakResponse.class);
            lenient().when(response.getStatus()).thenReturn(200);
            lenient().when(response.getBody()).thenReturn(Optional.of(introspectBody));

            when(keycloakClient.auth().authenticationByIntrospect(ACCESS_TOKEN)).thenReturn(response);

            // 실행 & 검증
            assertThatThrownBy(() -> introspector.introspect(ACCESS_TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class)
                .hasMessageContaining("유효하지 않습니다");
        }

        @Test
        void 응답_401이면_BadOpaqueTokenException이_발생한다() {
            // 준비
            @SuppressWarnings("unchecked")
            KeycloakResponse<KeycloakIntrospectResponse> response = mock(KeycloakResponse.class);
            lenient().when(response.getStatus()).thenReturn(401);

            when(keycloakClient.auth().authenticationByIntrospect(ACCESS_TOKEN)).thenReturn(response);

            // 실행 & 검증
            assertThatThrownBy(() -> introspector.introspect(ACCESS_TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class);
        }

        @Test
        void 통신_오류시_BadOpaqueTokenException이_발생한다() {
            // 준비
            when(keycloakClient.auth().authenticationByIntrospect(ACCESS_TOKEN))
                .thenThrow(new RestClientException("Connection refused"));

            // 실행 & 검증
            assertThatThrownBy(() -> introspector.introspect(ACCESS_TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class)
                .hasMessageContaining("통신 실패");
        }
    }

    // === Helper Methods ===

    private void mockIntrospectSuccess() {
        KeycloakIntrospectResponse introspectBody = mock(KeycloakIntrospectResponse.class);
        lenient().when(introspectBody.getActive()).thenReturn(true);

        @SuppressWarnings("unchecked")
        KeycloakResponse<KeycloakIntrospectResponse> response = mock(KeycloakResponse.class);
        lenient().when(response.getStatus()).thenReturn(200);
        lenient().when(response.getBody()).thenReturn(Optional.of(introspectBody));

        when(keycloakClient.auth().authenticationByIntrospect(ACCESS_TOKEN)).thenReturn(response);
    }

    private void mockUserInfoSuccess() {
        KeycloakUserInfo keycloakUserInfo = mock(KeycloakUserInfo.class);
        lenient().when(keycloakUserInfo.getSubject()).thenReturn(USER_SUB);
        lenient().when(keycloakUserInfo.getPreferredUsername()).thenReturn("testuser");
        lenient().when(keycloakUserInfo.getEmail()).thenReturn("test@example.com");
        lenient().when(keycloakUserInfo.getName()).thenReturn("Test User");
        lenient().when(keycloakUserInfo.getOtherInfo()).thenReturn(new HashMap<>());

        @SuppressWarnings("unchecked")
        KeycloakResponse<KeycloakUserInfo> response = mock(KeycloakResponse.class);
        lenient().when(response.getStatus()).thenReturn(200);
        lenient().when(response.getBody()).thenReturn(Optional.of(keycloakUserInfo));

        when(keycloakClient.user().getUserInfo(ACCESS_TOKEN)).thenReturn(response);
    }
}
