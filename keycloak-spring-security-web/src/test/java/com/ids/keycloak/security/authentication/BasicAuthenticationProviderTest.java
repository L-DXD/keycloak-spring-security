package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BasicAuthenticationProviderTest {

    private BasicAuthenticationProvider provider;

    @Mock
    private KeycloakAuthenticationProvider oidcProvider;

    private static final String TOKEN_ENDPOINT = "http://keycloak:8080/realms/test/protocol/openid-connect/token";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";

    @BeforeEach
    void setUp() {
        provider = new BasicAuthenticationProvider(TOKEN_ENDPOINT, CLIENT_ID, CLIENT_SECRET, oidcProvider);
    }

    @Test
    void supports_BasicAuthenticationToken만_지원한다() {
        assertThat(provider.supports(BasicAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(KeycloakAuthentication.class)).isFalse();
    }

    @Nested
    class 인증_실패_테스트 {

        @Test
        void 유효하지_않은_토큰_엔드포인트로_호출하면_AuthenticationFailedException이_발생한다() {
            BasicAuthenticationToken token = new BasicAuthenticationToken("user", "wrongpass");

            BasicAuthenticationProvider badProvider = new BasicAuthenticationProvider(
                "http://invalid-host:9999/token",
                CLIENT_ID,
                CLIENT_SECRET,
                oidcProvider
            );

            assertThatThrownBy(() -> badProvider.authenticate(token))
                .isInstanceOf(AuthenticationFailedException.class)
                .hasMessageContaining("Basic Auth 인증 실패");
        }
    }
}
