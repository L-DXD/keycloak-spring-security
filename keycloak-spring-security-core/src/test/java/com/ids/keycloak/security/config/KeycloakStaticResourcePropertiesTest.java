package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link KeycloakStaticResourceProperties} 회귀 테스트.
 *
 * <p>C-A: {@link KeycloakStaticResourceProperties#isFilterSkipEffective()}가 더 이상
 * {@code filterSkip} 단독으로 결정되지 않고 {@code permitAll}에도 종속된다는 조합표를 고정한다
 * ({@code enabled && filterSkip && permitAll}). {@code permitAll=false}(기본값)인 상태에서
 * {@code filterSkip}만 true여도 필터 스킵이 적용되면 안 된다 — 그렇지 않으면 정적 리소스에서
 * SecurityContext가 영구 미인증 상태로 고정되어 무한 리다이렉트 루프가 발생한다(클래스 Javadoc 참고).
 */
class KeycloakStaticResourcePropertiesTest {

    @Nested
    @DisplayName("기본값 검증")
    class 기본값_검증 {

        @Test
        void 기본_enabled는_true이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.isEnabled()).isTrue();
        }

        @Test
        void 기본_filterSkip은_true이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.isFilterSkip()).isTrue();
        }

        @Test
        void 기본_permitAll은_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.isPermitAll()).isFalse();
        }

        @Test
        void 기본_patterns는_Spring_Boot_정적_리소스_4종이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.getPatterns())
                .containsExactly("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico");
        }

        @Test
        void 기본값_조합에서는_isFilterSkipEffective가_false이다() {
            // C-A 핵심 회귀: filterSkip=true(기본값)이어도 permitAll=false(기본값)이면
            // 필터 스킵이 실제로 적용되면 안 된다 — 무한 리다이렉트 루프 방지.
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.isFilterSkipEffective()).isFalse();
        }

        @Test
        void 기본값_조합에서는_isPermitAllEffective가_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();

            assertThat(properties.isPermitAllEffective()).isFalse();
        }
    }

    @Nested
    @DisplayName("C-A: isFilterSkipEffective() 조합표 (enabled x filterSkip x permitAll)")
    class isFilterSkipEffective_조합표 {

        @Test
        void enabled_filterSkip_permitAll_모두_true이면_true이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(true);
            properties.setFilterSkip(true);
            properties.setPermitAll(true);

            assertThat(properties.isFilterSkipEffective()).isTrue();
        }

        @Test
        void permitAll이_false이면_filterSkip이_true여도_false이다() {
            // C-A 핵심: "인증 스킵"과 "인가 면제"는 독립적으로 켤 수 없다.
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(true);
            properties.setFilterSkip(true);
            properties.setPermitAll(false);

            assertThat(properties.isFilterSkipEffective()).isFalse();
        }

        @Test
        void filterSkip이_false이면_permitAll이_true여도_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(true);
            properties.setFilterSkip(false);
            properties.setPermitAll(true);

            assertThat(properties.isFilterSkipEffective()).isFalse();
        }

        @Test
        void enabled가_false이면_filterSkip과_permitAll이_모두_true여도_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(false);
            properties.setFilterSkip(true);
            properties.setPermitAll(true);

            assertThat(properties.isFilterSkipEffective()).isFalse();
        }

        @Test
        void 모두_false이면_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(false);
            properties.setFilterSkip(false);
            properties.setPermitAll(false);

            assertThat(properties.isFilterSkipEffective()).isFalse();
        }
    }

    @Nested
    @DisplayName("isPermitAllEffective() 조합")
    class isPermitAllEffective_조합 {

        @Test
        void enabled와_permitAll이_모두_true이면_true이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(true);
            properties.setPermitAll(true);

            assertThat(properties.isPermitAllEffective()).isTrue();
        }

        @Test
        void enabled가_false이면_permitAll이_true여도_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(false);
            properties.setPermitAll(true);

            assertThat(properties.isPermitAllEffective()).isFalse();
        }

        @Test
        void permitAll이_false이면_enabled가_true여도_false이다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setEnabled(true);
            properties.setPermitAll(false);

            assertThat(properties.isPermitAllEffective()).isFalse();
        }
    }

    @Nested
    @DisplayName("Setter 검증")
    class Setter_검증 {

        @Test
        void patterns를_설정할_수_있다() {
            KeycloakStaticResourceProperties properties = new KeycloakStaticResourceProperties();
            properties.setPatterns(java.util.List.of("/static/**"));

            assertThat(properties.getPatterns()).containsExactly("/static/**");
        }
    }
}
