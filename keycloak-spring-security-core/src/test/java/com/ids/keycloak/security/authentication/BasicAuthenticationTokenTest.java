package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

class BasicAuthenticationTokenTest {

    @Nested
    class 인증_전_토큰 {

        @Test
        void 미인증_토큰을_생성하면_authenticated는_false이다() {
            BasicAuthenticationToken token = new BasicAuthenticationToken("user", "pass");

            assertThat(token.isAuthenticated()).isFalse();
            assertThat(token.getUsername()).isEqualTo("user");
            assertThat(token.getPassword()).isEqualTo("pass");
            assertThat(token.getCredentials()).isEqualTo("pass");
            assertThat(token.getPrincipal()).isEqualTo("user");
            assertThat(token.getAuthorities()).isEmpty();
        }

        @Test
        void getIdToken과_getAccessToken은_null이다() {
            BasicAuthenticationToken token = new BasicAuthenticationToken("user", "pass");

            assertThat(token.getIdToken()).isNull();
            assertThat(token.getAccessToken()).isNull();
        }
    }

    @Nested
    class 인증_후_토큰 {

        @Test
        void 인증_완료_토큰은_authenticated가_true이고_Principal이_설정된다() {
            OidcIdToken oidcIdToken = new OidcIdToken(
                "id-token-value", Instant.now(), Instant.now().plusSeconds(3600),
                Map.of("sub", "user-123")
            );
            KeycloakPrincipal principal = new KeycloakPrincipal("user-123", List.of(), oidcIdToken, null);

            BasicAuthenticationToken token = new BasicAuthenticationToken(principal, "id-token", "access-token");

            assertThat(token.isAuthenticated()).isTrue();
            assertThat(token.getPrincipal()).isInstanceOf(KeycloakPrincipal.class);
            assertThat(((KeycloakPrincipal) token.getPrincipal()).getName()).isEqualTo("user-123");
            assertThat(token.getIdToken()).isEqualTo("id-token");
            assertThat(token.getAccessToken()).isEqualTo("access-token");
            assertThat(token.getPassword()).isNull();
            assertThat(token.getCredentials()).isNull();
        }
    }

    @Nested
    class eraseCredentials_테스트 {

        @Test
        void eraseCredentials_호출_시_password가_null이_된다() {
            BasicAuthenticationToken token = new BasicAuthenticationToken("user", "pass");
            assertThat(token.getPassword()).isEqualTo("pass");

            token.eraseCredentials();

            assertThat(token.getPassword()).isNull();
            assertThat(token.getCredentials()).isNull();
        }
    }
}
