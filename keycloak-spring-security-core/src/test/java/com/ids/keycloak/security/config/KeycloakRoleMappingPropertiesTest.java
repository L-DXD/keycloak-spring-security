package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakRoleMappingProperties} 단위 테스트.
 *
 * <p>보안 Advisory 7(CWE-863) 재현을 막기 위한 {@link KeycloakRoleMappingProperties#validate()}
 * 가드레일을 검증합니다: {@link RoleMappingMode#SEPARATE_NAMESPACE}에서 realm/client 접두사가
 * 공백이거나 서로 같으면 네임스페이스 분리가 무력화되므로 기동 시 즉시 실패해야 합니다.</p>
 */
class KeycloakRoleMappingPropertiesTest {

    @Nested
    class 기본값_검증 {

        @Test
        void 기본_mode는_SEPARATE_NAMESPACE이다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();

            assertThat(properties.getMode()).isEqualTo(RoleMappingMode.SEPARATE_NAMESPACE);
        }

        @Test
        void 기본_realmRolePrefix는_ROLE_REALM_이다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();

            assertThat(properties.getRealmRolePrefix()).isEqualTo("ROLE_REALM_");
        }

        @Test
        void 기본_clientRolePrefix는_ROLE_CLIENT_이다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();

            assertThat(properties.getClientRolePrefix()).isEqualTo("ROLE_CLIENT_");
        }

        @Test
        void 기본_설정은_validate를_통과한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();

            assertThatCode(properties::validate).doesNotThrowAnyException();
        }
    }

    @Nested
    class SEPARATE_NAMESPACE_접두사_가드레일 {

        @Test
        void realmRolePrefix가_공백이면_기동이_실패한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setRealmRolePrefix("   ");

            assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("realm-role-prefix");
        }

        @Test
        void realmRolePrefix가_null이면_기동이_실패한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setRealmRolePrefix(null);

            assertThatThrownBy(properties::validate).isInstanceOf(IllegalStateException.class);
        }

        @Test
        void clientRolePrefix가_공백이면_기동이_실패한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setClientRolePrefix("");

            assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-role-prefix");
        }

        @Test
        void realm과_client_접두사가_동일하면_기동이_실패한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setRealmRolePrefix("ROLE_SAME_");
            properties.setClientRolePrefix("ROLE_SAME_");

            assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("동일");
        }

        @Test
        void 접두사가_서로_다르면_기동이_성공한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setRealmRolePrefix("ROLE_R_");
            properties.setClientRolePrefix("ROLE_C_");

            assertThatCode(properties::validate).doesNotThrowAnyException();
        }
    }

    @Nested
    class 단일_소스_모드는_접두사_가드레일_대상이_아니다 {

        @Test
        void REALM_ONLY_모드는_접두사가_공백이거나_동일해도_통과한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setMode(RoleMappingMode.REALM_ONLY);
            properties.setRealmRolePrefix("");
            properties.setClientRolePrefix("");

            assertThatCode(properties::validate).doesNotThrowAnyException();
        }

        @Test
        void CLIENT_ONLY_모드는_접두사가_공백이거나_동일해도_통과한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setMode(RoleMappingMode.CLIENT_ONLY);
            properties.setRealmRolePrefix("SAME");
            properties.setClientRolePrefix("SAME");

            assertThatCode(properties::validate).doesNotThrowAnyException();
        }

        @Test
        void LEGACY_MERGED_모드는_접두사가_공백이거나_동일해도_통과한다() {
            KeycloakRoleMappingProperties properties = new KeycloakRoleMappingProperties();
            properties.setMode(RoleMappingMode.LEGACY_MERGED);
            properties.setRealmRolePrefix(null);
            properties.setClientRolePrefix(null);

            assertThatCode(properties::validate).doesNotThrowAnyException();
        }
    }
}
