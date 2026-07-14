package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.ids.keycloak.security.config.KeycloakRoleMappingProperties;
import com.ids.keycloak.security.config.RoleMappingMode;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

/**
 * {@link KeycloakAuthorityExtractor} 단위 테스트.
 *
 * <p>보안 Advisory 7(CWE-863) 대응 검증: realm 역할과 client 역할이 동일한 이름을 가져도
 * {@link RoleMappingMode#SEPARATE_NAMESPACE}(기본값)에서는 서로 다른 GrantedAuthority로 분리되어야
 * 하며, 이름 충돌로 인한 의도치 않은 인가 통과가 불가능해야 합니다.</p>
 */
class KeycloakAuthorityExtractorTest {

    private static final String CLIENT_ID = "target-client";

    private static Map<String, Object> claimsWithRealmAndClientRoles(
            String clientId, List<String> realmRoles, List<String> clientRoles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", realmRoles));
        claims.put("resource_access", Map.of(clientId, Map.of("roles", clientRoles)));
        return claims;
    }

    private static Map<String, Object> claimsWithRealmRolesOnly(List<String> realmRoles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", realmRoles));
        return claims;
    }

    private static Set<String> authorityStrings(Collection<GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
    }

    @Nested
    class SEPARATE_NAMESPACE_기본_동작 {

        @Test
        void realm_역할은_ROLE_REALM_접두사로_변환된다() {
            Map<String, Object> claims = claimsWithRealmRolesOnly(List.of("ADMIN"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, CLIENT_ID);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_REALM_ADMIN");
        }

        @Test
        void client_역할은_ROLE_CLIENT_정규화된_clientId_접두사로_변환된다() {
            Map<String, Object> claims = claimsWithRealmAndClientRoles(CLIENT_ID, List.of(), List.of("ADMIN"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, CLIENT_ID);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_CLIENT_TARGET_CLIENT_ADMIN");
        }

        /**
         * 핵심 검증: 동일 이름("ADMIN")의 realm 역할과 client 역할이 서로 다른 두 개의
         * GrantedAuthority로 분리되어야 하며, 병합된 단일 "ROLE_ADMIN"으로 충돌해서는 안 된다. 이
         * 분리 덕분에 client 전용 인가 검사(실제로는
         * {@code hasAuthority("ROLE_CLIENT_TARGET_CLIENT_ADMIN")})를 realm ADMIN 보유자가 우회할 수
         * 없다.
         */
        @Test
        void 동명_realm_client_역할이_서로_다른_권한으로_분리되어_이름_충돌_오인가가_불가능하다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("ADMIN"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, CLIENT_ID);

            assertThat(authorities).hasSize(2);
            assertThat(authorityStrings(authorities))
                .containsExactlyInAnyOrder("ROLE_REALM_ADMIN", "ROLE_CLIENT_TARGET_CLIENT_ADMIN")
                .doesNotContain("ROLE_ADMIN");
        }

        @Test
        void 명시적으로_기본_KeycloakRoleMappingProperties를_전달해도_동일하게_분리된다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("ADMIN"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorityStrings(authorities))
                .containsExactlyInAnyOrder("ROLE_REALM_ADMIN", "ROLE_CLIENT_TARGET_CLIENT_ADMIN");
        }
    }

    @Nested
    class REALM_ONLY_모드 {

        @Test
        void realm_역할만_추출되고_ROLE_접두사가_붙는다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("VIEWER"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.REALM_ONLY);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_ADMIN");
        }

        @Test
        void client_역할은_무시된다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of(), List.of("VIEWER"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.REALM_ONLY);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorities).isEmpty();
        }
    }

    @Nested
    class CLIENT_ONLY_모드 {

        @Test
        void client_역할만_추출되고_ROLE_접두사가_붙는다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("VIEWER"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.CLIENT_ONLY);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_VIEWER");
        }

        @Test
        void realm_역할은_무시된다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of());
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.CLIENT_ONLY);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorities).isEmpty();
        }

        @Test
        void clientId가_null이면_client_역할도_추출되지_않는다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of(), List.of("VIEWER"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.CLIENT_ONLY);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, null, mapping);

            assertThat(authorities).isEmpty();
        }
    }

    @Nested
    class LEGACY_MERGED_모드_과거_취약_동작_재현 {

        @Test
        void realm과_client_역할_모두_ROLE_접두사로_병합된다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("VIEWER"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.LEGACY_MERGED);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorityStrings(authorities)).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_VIEWER");
        }

        /**
         * 과거(취약) 동작 재현: 동명의 realm/client 역할이 동일한 "ROLE_ADMIN"으로 병합되어 서로
         * 구분할 수 없다 (Advisory 7이 지적한 CWE-863 문제 상황 그 자체).
         */
        @Test
        void 동명_realm_client_역할이_병합되어_구분되지_않는다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles(CLIENT_ID, List.of("ADMIN"), List.of("ADMIN"));
            KeycloakRoleMappingProperties mapping = new KeycloakRoleMappingProperties();
            mapping.setMode(RoleMappingMode.LEGACY_MERGED);

            Collection<GrantedAuthority> authorities =
                KeycloakAuthorityExtractor.extract(claims, CLIENT_ID, mapping);

            assertThat(authorities).hasSize(1);
            assertThat(authorityStrings(authorities)).containsExactly("ROLE_ADMIN");
        }
    }

    @Nested
    class clientId_정규화 {

        @Test
        void 하이픈은_밑줄로_치환되고_대문자화된다() {
            Map<String, Object> claims =
                claimsWithRealmAndClientRoles("target-client", List.of(), List.of("VIEWER"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, "target-client");

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_CLIENT_TARGET_CLIENT_VIEWER");
        }

        @Test
        void 연속된_특수문자는_단일_밑줄로_축약된다() {
            String clientId = "target--client..app";
            Map<String, Object> claims = claimsWithRealmAndClientRoles(clientId, List.of(), List.of("VIEWER"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

            assertThat(authorityStrings(authorities))
                .containsExactly("ROLE_CLIENT_TARGET_CLIENT_APP_VIEWER");
        }

        @Test
        void 선행_후행_특수문자는_제거된다() {
            String clientId = "-target-client-";
            Map<String, Object> claims = claimsWithRealmAndClientRoles(clientId, List.of(), List.of("VIEWER"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_CLIENT_TARGET_CLIENT_VIEWER");
        }

        @Test
        void 정규화_결과가_비면_UNKNOWN으로_대체된다() {
            String clientId = "---";
            Map<String, Object> claims = claimsWithRealmAndClientRoles(clientId, List.of(), List.of("VIEWER"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_CLIENT_UNKNOWN_VIEWER");
        }
    }

    @Nested
    class 대소문자_처리_비대칭은_의도된_설계 {

        @Test
        void 역할명은_원본_대소문자를_그대로_유지한다() {
            Map<String, Object> claims = claimsWithRealmRolesOnly(List.of("Admin"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, CLIENT_ID);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_REALM_Admin");
        }

        @Test
        void clientId는_대문자로_정규화되지만_역할명은_그대로_유지된다() {
            String clientId = "Target-Client";
            Map<String, Object> claims = claimsWithRealmAndClientRoles(clientId, List.of(), List.of("Viewer"));

            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

            assertThat(authorityStrings(authorities)).containsExactly("ROLE_CLIENT_TARGET_CLIENT_Viewer");
        }
    }

    @Nested
    class 빈_또는_null_클레임 {

        @Test
        void claims가_null이면_빈_컬렉션을_반환한다() {
            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(null, CLIENT_ID);

            assertThat(authorities).isEmpty();
        }

        @Test
        void claims가_비어있으면_빈_컬렉션을_반환한다() {
            Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(Map.of(), CLIENT_ID);

            assertThat(authorities).isEmpty();
        }
    }
}
