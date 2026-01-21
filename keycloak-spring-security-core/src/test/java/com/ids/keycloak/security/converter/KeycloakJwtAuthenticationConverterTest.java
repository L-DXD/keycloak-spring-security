package com.ids.keycloak.security.converter;

import com.ids.keycloak.security.exception.AuthorityMappingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakJwtAuthenticationConverterTest {

    private static final String CLIENT_ID = "test-client";
    private KeycloakJwtAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new KeycloakJwtAuthenticationConverter(CLIENT_ID);
    }

    private Jwt createJwt(Map<String, Object> claims) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claims(c -> c.putAll(claims))
                .build();
    }

    @Nested
    class ConvertTests {

        @Nested
        class 성공_테스트 {
            @Test
            void JWT를_Authentication으로_변환_성공() {
                // given
                Map<String, Object> claims = Map.of(
                        "preferred_username", "testuser",
                        "realm_access", Map.of("roles", List.of("user")),
                        "resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("client-admin")))
                );
                Jwt jwt = createJwt(claims);

                // when
                JwtAuthenticationToken token = converter.convert(jwt);

                // then
                assertThat(token).isNotNull();
                assertThat(token.getName()).isEqualTo("testuser");
                Set<String> authorities = token.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                assertThat(authorities).containsExactlyInAnyOrder("ROLE_user", "ROLE_client-admin");
            }

            @Test
            void 실제_페이로드와_유사한_JWT로_변환_성공() {
                // given
                KeycloakJwtAuthenticationConverter workmngmConverter = new KeycloakJwtAuthenticationConverter("workmngm");

                Map<String, Object> realmAccess = Map.of(
                    "roles", List.of("default-roles-dcm-realm", "offline_access", "uma_authorization")
                );
                Map<String, Object> workmngmAccess = Map.of("roles", List.of("PT"));
                Map<String, Object> accountAccess = Map.of("roles", List.of("manage-account", "view-profile"));
                Map<String, Object> resourceAccess = Map.of(
                    "workmngm", workmngmAccess,
                    "account", accountAccess
                );

                Map<String, Object> claims = Map.of(
                    "preferred_username", "worktest7",
                    "realm_access", realmAccess,
                    "resource_access", resourceAccess
                );

                Jwt jwt = createJwt(claims);

                // when
                JwtAuthenticationToken token = workmngmConverter.convert(jwt);

                // then
                assertThat(token.getName()).isEqualTo("worktest7");

                Set<String> authorities = token.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

                assertThat(authorities).containsExactlyInAnyOrder(
                    "ROLE_default-roles-dcm-realm",
                    "ROLE_offline_access",
                    "ROLE_uma_authorization",
                    "ROLE_PT"
                );
                
                // Also verify that 'account' roles are not included
                assertThat(authorities).doesNotContain(
                    "ROLE_manage-account",
                    "ROLE_view-profile"
                );
            }
        }
    }

    @Nested
    class ExtractRolesTests {

        @Nested
        class 성공_테스트 {
            @Test
            void realm_역할만_추출_성공() {
                // given
                Map<String, Object> claims = Map.of(
                        "realm_access", Map.of("roles", List.of("realm-user", "realm-admin"))
                );
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();
                
                // then
                assertThat(authorities).hasSize(2);
                Set<String> authorityStrings = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
                assertThat(authorityStrings).containsExactlyInAnyOrder("ROLE_realm-user", "ROLE_realm-admin");
            }

            @Test
            void client_역할만_추출_성공() {
                // given
                Map<String, Object> claims = Map.of(
                        "resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("client-user")))
                );
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();

                // then
                assertThat(authorities).hasSize(1);
                assertThat(authorities.iterator().next().getAuthority()).isEqualTo("ROLE_client-user");
            }

            @Test
            void realm과_client_역할을_모두_추출_성공() {
                // given
                Map<String, Object> claims = Map.of(
                        "realm_access", Map.of("roles", List.of("user")),
                        "resource_access", Map.of(CLIENT_ID, Map.of("roles", List.of("admin")))
                );
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();

                // then
                assertThat(authorities).hasSize(2);
                Set<String> authorityStrings = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
                assertThat(authorityStrings).containsExactlyInAnyOrder("ROLE_user", "ROLE_admin");
            }
        }

        @Nested
        class 바운더리_테스트 {
            @Test
            void 다른_clientId의_역할은_무시() {
                // given
                Map<String, Object> claims = Map.of(
                        "resource_access", Map.of("other-client", Map.of("roles", List.of("other-role")))
                );
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();

                // then
                assertThat(authorities).isEmpty();
            }
            
            @Test
            void 역할_클레임이_없으면_빈_컬렉션_반환() {
                // given
                Map<String, Object> claims = Map.of("preferred_username", "user-without-roles");
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();

                // then
                assertThat(authorities).isEmpty();
            }

            @Test
            void 역할_리스트에_null이_있으면_무시하고_처리() {
                // given
                Map<String, Object> claims = Map.of(
                        "realm_access", Map.of("roles", Arrays.asList("user", null, "admin"))
                );
                Jwt jwt = createJwt(claims);

                // when
                Collection<GrantedAuthority> authorities = converter.convert(jwt).getAuthorities();

                // then
                assertThat(authorities).hasSize(2);
                Set<String> authorityStrings = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
                assertThat(authorityStrings).containsExactlyInAnyOrder("ROLE_user", "ROLE_admin");
            }
        }
    }
}
