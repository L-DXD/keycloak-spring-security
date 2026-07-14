package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakSecurityProperties}에 {@code roleMapping} 필드가 올바르게 구성되고,
 * {@link KeycloakSecurityProperties#afterPropertiesSet()}이 보안 Advisory 7(CWE-863) 가드레일
 * ({@link KeycloakRoleMappingProperties#validate()})을 실제로 위임·실행해 오설정 시 기동을
 * 실패시키는지 검증합니다.
 */
class KeycloakSecurityPropertiesRoleMappingTest {

    @Nested
    class roleMapping_필드_기본값 {

        @Test
        void roleMapping_프로퍼티가_null이_아니다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThat(properties.getRoleMapping()).isNotNull();
        }

        @Test
        void roleMapping_기본_mode는_SEPARATE_NAMESPACE이다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThat(properties.getRoleMapping().getMode()).isEqualTo(RoleMappingMode.SEPARATE_NAMESPACE);
        }
    }

    @Nested
    class afterPropertiesSet_정상_설정_통과 {

        @Test
        void 기본_설정으로는_기동이_성공한다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

            assertThatCode(properties::afterPropertiesSet).doesNotThrowAnyException();
        }

        @Test
        void 서로_다른_접두사로_명시_설정해도_기동이_성공한다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();
            properties.getRoleMapping().setRealmRolePrefix("ROLE_R_");
            properties.getRoleMapping().setClientRolePrefix("ROLE_C_");

            assertThatCode(properties::afterPropertiesSet).doesNotThrowAnyException();
        }
    }

    @Nested
    class afterPropertiesSet_오설정_시_기동이_실패한다 {

        @Test
        void realmRolePrefix가_공백이면_IllegalStateException으로_기동이_실패한다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();
            properties.getRoleMapping().setRealmRolePrefix(" ");

            assertThatThrownBy(properties::afterPropertiesSet).isInstanceOf(IllegalStateException.class);
        }

        @Test
        void clientRolePrefix가_공백이면_IllegalStateException으로_기동이_실패한다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();
            properties.getRoleMapping().setClientRolePrefix("");

            assertThatThrownBy(properties::afterPropertiesSet).isInstanceOf(IllegalStateException.class);
        }

        @Test
        void realm과_client_접두사가_동일하면_IllegalStateException으로_기동이_실패한다() {
            KeycloakSecurityProperties properties = new KeycloakSecurityProperties();
            properties.getRoleMapping().setRealmRolePrefix("ROLE_DUP_");
            properties.getRoleMapping().setClientRolePrefix("ROLE_DUP_");

            assertThatThrownBy(properties::afterPropertiesSet).isInstanceOf(IllegalStateException.class);
        }
    }
}
