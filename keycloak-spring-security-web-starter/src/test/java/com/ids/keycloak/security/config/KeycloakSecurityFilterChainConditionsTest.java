package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.ids.keycloak.security.manager.KeycloakAuthorizationManager;
import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * {@code keycloakSecurityFilterChain} Bean의 조건/순서 어노테이션이 Fail-Open 방지 설계를 유지하는지 검증합니다.
 * <p>
 * (CVSS 8.1, CWE-1188/863) 회귀 방지 — 다음 보증이 깨지면 인증이 통째로 사라질 수 있으므로 어노테이션 수준에서 고정합니다.
 * 전체 AutoConfiguration은 Keycloak/OAuth2 협력 빈이 많아 풀 컨텍스트 기동이 비현실적이라, 조건을 직접 검증합니다.
 * </p>
 * <ul>
 *   <li>(a) 기본 등록: {@code @ConditionalOnProperty(matchIfMissing=true)} → 프로퍼티 미설정 시에도 등록</li>
 *   <li>(b) 사용자 체인 공존: {@code @ConditionalOnMissingBean(name=...)} → SecurityFilterChain.class 타입 충돌로 비활성화되지 않음</li>
 *   <li>(c) 명시적 opt-out: {@code auto-filter-chain=false} 일 때만 미등록</li>
 *   <li>순서: {@code @Order(LOWEST_PRECEDENCE)} → catch-all 체인이 맨 뒤, 사용자의 구체적 체인이 우선</li>
 * </ul>
 */
class KeycloakSecurityFilterChainConditionsTest {

    private Method filterChainMethod() throws NoSuchMethodException {
        return KeycloakServletAutoConfiguration.KeycloakWebSecurityConfiguration.class.getDeclaredMethod(
            "keycloakSecurityFilterChain",
            HttpSecurity.class,
            KeycloakSecurityProperties.class,
            ObjectProvider.class,
            KeycloakAuthorizationManager.class
        );
    }

    @Test
    @DisplayName("(b) Bean 이름 기반 @ConditionalOnMissingBean — 사용자가 다른 SecurityFilterChain을 추가해도 공존")
    void conditionalOnMissingBeanByName() throws Exception {
        ConditionalOnMissingBean annotation = filterChainMethod().getAnnotation(ConditionalOnMissingBean.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.name()).containsExactly("keycloakSecurityFilterChain");
        // 타입 기반 조건(SecurityFilterChain.class)이 남아 있으면 Fail-Open이 재발하므로 비어 있어야 한다
        assertThat(annotation.value()).isEmpty();
    }

    @Test
    @DisplayName("(a)(c) @ConditionalOnProperty — 기본 등록(matchIfMissing), auto-filter-chain=false 일 때만 미등록")
    void conditionalOnProperty() throws Exception {
        ConditionalOnProperty annotation = filterChainMethod().getAnnotation(ConditionalOnProperty.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.prefix()).isEqualTo("keycloak.security");
        assertThat(annotation.name()).containsExactly("auto-filter-chain");
        assertThat(annotation.havingValue()).isEqualTo("true");
        assertThat(annotation.matchIfMissing()).isTrue();
    }

    @Test
    @DisplayName("@Order(LOWEST_PRECEDENCE) — catch-all 체인이 맨 뒤, 사용자 체인이 우선 평가됨")
    void orderIsLowestPrecedence() throws Exception {
        Order annotation = filterChainMethod().getAnnotation(Order.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
    }

    @Test
    @DisplayName("@Bean 이름이 'keycloakSecurityFilterChain'으로 고정 (조건의 name과 일치)")
    void beanNameMatches() throws Exception {
        Bean annotation = filterChainMethod().getAnnotation(Bean.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).containsExactly("keycloakSecurityFilterChain");
    }
}
