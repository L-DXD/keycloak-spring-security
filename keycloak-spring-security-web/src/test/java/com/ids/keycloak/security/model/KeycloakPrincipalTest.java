package com.ids.keycloak.security.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * {@link KeycloakPrincipal} 단위 테스트.
 * OAuth2AuthenticatedPrincipal 인터페이스 추가에 대한 검증 포함.
 */
class KeycloakPrincipalTest {

    private KeycloakPrincipal principal;
    private OidcIdToken idToken;
    private OidcUserInfo userInfo;
    private Collection<? extends GrantedAuthority> authorities;

    private static final String USER_SUB = "user-123";

    @BeforeEach
    void setUp() {
        idToken = new OidcIdToken(
            "token-value",
            Instant.now(),
            Instant.now().plusSeconds(3600),
            Map.of("sub", USER_SUB, "iss", "https://keycloak.example.com")
        );
        userInfo = new OidcUserInfo(Map.of(
            "sub", USER_SUB,
            "preferred_username", "testuser",
            "email", "test@example.com"
        ));
        authorities = List.of(
            new SimpleGrantedAuthority("ROLE_admin"),
            new SimpleGrantedAuthority("ROLE_user")
        );

        principal = new KeycloakPrincipal(USER_SUB, authorities, idToken, userInfo);
    }

    @Nested
    class 인터페이스_호환성_테스트 {

        @Test
        void OidcUser_인터페이스를_구현한다() {
            assertThat(principal).isInstanceOf(OidcUser.class);
        }

        @Test
        void OAuth2AuthenticatedPrincipal_인터페이스를_구현한다() {
            assertThat(principal).isInstanceOf(OAuth2AuthenticatedPrincipal.class);
        }
    }

    @Nested
    class 기본_동작_테스트 {

        @Test
        void getName은_subject를_반환한다() {
            assertThat(principal.getName()).isEqualTo(USER_SUB);
        }

        @Test
        void getAuthorities는_권한_목록을_반환한다() {
            assertThat(principal.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_admin", "ROLE_user");
        }

        @Test
        void getAttributes는_ID_Token과_UserInfo_클레임을_합쳐서_반환한다() {
            Map<String, Object> attributes = principal.getAttributes();
            assertThat(attributes).containsKey("sub");
            assertThat(attributes).containsKey("preferred_username");
            assertThat(attributes).containsKey("email");
            assertThat(attributes).containsKey("iss");
        }

        @Test
        void getClaims는_getAttributes와_동일한_결과를_반환한다() {
            assertThat(principal.getClaims()).isEqualTo(principal.getAttributes());
        }

        @Test
        void getIdToken은_OidcIdToken을_반환한다() {
            assertThat(principal.getIdToken()).isEqualTo(idToken);
        }

        @Test
        void getUserInfo는_OidcUserInfo를_반환한다() {
            assertThat(principal.getUserInfo()).isEqualTo(userInfo);
        }
    }

    @Nested
    class UserInfo_null_테스트 {

        @Test
        void UserInfo가_null이면_ID_Token_클레임만_반환한다() {
            KeycloakPrincipal principalWithoutUserInfo =
                new KeycloakPrincipal(USER_SUB, authorities, idToken, null);

            Map<String, Object> attributes = principalWithoutUserInfo.getAttributes();
            assertThat(attributes).containsKey("sub");
            assertThat(attributes).containsKey("iss");
            assertThat(attributes).doesNotContainKey("preferred_username");
        }
    }
}
