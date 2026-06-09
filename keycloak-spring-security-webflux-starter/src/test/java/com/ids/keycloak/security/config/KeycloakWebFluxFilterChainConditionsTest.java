package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.ids.keycloak.security.filter.ReactiveAuthLoggingFilter;
import com.ids.keycloak.security.filter.ReactiveBackChannelLogoutEndpointFilter;
import com.ids.keycloak.security.filter.ReactiveLoggingFilter;
import com.ids.keycloak.security.web.reactive.KeycloakServerAccessDeniedHandler;
import com.ids.keycloak.security.web.reactive.KeycloakServerAuthenticationEntryPoint;
import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * {@code keycloakSecurityWebFilterChain} Bean의 조건/순서 어노테이션이
 * Fail-Open 방지 설계를 유지하는지 검증합니다.
 *
 * <p>(CVSS 8.1, CWE-1188/863) 회귀 방지 — WebFlux 버전의 조건을 고정합니다.</p>
 */
class KeycloakWebFluxFilterChainConditionsTest {

  /**
   * keycloakSecurityWebFilterChain 메서드를 리플렉션으로 조회합니다.
   */
  private Method filterChainMethod() throws NoSuchMethodException {
    return KeycloakWebFluxAutoConfiguration.KeycloakWebSecurityConfiguration.class
        .getDeclaredMethod(
            "keycloakSecurityWebFilterChain",
            ServerHttpSecurity.class,
            ReactiveAuthenticationManager.class,
            KeycloakServerAuthenticationEntryPoint.class,
            KeycloakServerAccessDeniedHandler.class,
            KeycloakSecurityProperties.class,
            com.sd.KeycloakClient.factory.KeycloakClient.class,
            KeycloakWebFluxAutoConfiguration.KeycloakInfrastructureConfiguration.KeycloakConfig.class,
            com.ids.keycloak.security.session.ReactiveSessionManager.class,
            ObjectProvider.class,  // RateLimiter
            ObjectProvider.class,  // ReactiveLoggingFilter
            ObjectProvider.class,  // ReactiveAuthLoggingFilter
            ObjectProvider.class,  // ReactiveClientRegistrationRepository
            ObjectProvider.class,  // ReactiveOAuth2AuthorizedClientService
            ObjectProvider.class   // ReactiveBackChannelLogoutEndpointFilter
        );
  }

  @Test
  @DisplayName("(b) Bean 이름 기반 @ConditionalOnMissingBean — 사용자 SecurityWebFilterChain 공존")
  void conditionalOnMissingBeanByName() throws Exception {
    ConditionalOnMissingBean annotation =
        filterChainMethod().getAnnotation(ConditionalOnMissingBean.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.name()).containsExactly("keycloakSecurityWebFilterChain");
    // 타입 기반 조건이면 Fail-Open 재발 → 반드시 비어있어야 함
    assertThat(annotation.value()).isEmpty();
  }

  @Test
  @DisplayName("(a)(c) @ConditionalOnProperty — 기본 등록(matchIfMissing), auto-filter-chain=false 일 때만 미등록")
  void conditionalOnProperty() throws Exception {
    ConditionalOnProperty annotation =
        filterChainMethod().getAnnotation(ConditionalOnProperty.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.prefix()).isEqualTo("keycloak.security");
    assertThat(annotation.name()).containsExactly("auto-filter-chain");
    assertThat(annotation.havingValue()).isEqualTo("true");
    assertThat(annotation.matchIfMissing()).isTrue();
  }

  @Test
  @DisplayName("@Order(LOWEST_PRECEDENCE) — catch-all 체인이 맨 뒤")
  void orderIsLowestPrecedence() throws Exception {
    Order annotation = filterChainMethod().getAnnotation(Order.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.value()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
  }

  @Test
  @DisplayName("@Bean 이름이 'keycloakSecurityWebFilterChain'으로 고정")
  void beanNameMatches() throws Exception {
    Bean annotation = filterChainMethod().getAnnotation(Bean.class);

    assertThat(annotation).isNotNull();
    assertThat(annotation.value()).containsExactly("keycloakSecurityWebFilterChain");
  }
}
