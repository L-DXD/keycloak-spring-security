package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;

import com.ids.keycloak.security.authentication.KeycloakAuthenticationProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * {@link KeycloakServletAutoConfiguration.KeycloakAuthenticationConfiguration}의
 * 보안 High #2 대응(name 기반 조건 + {@code @Qualifier} 배선)을 {@link ApplicationContextRunner}로
 * 검증하는 통합 테스트입니다.
 *
 * <p>{@code KeycloakBackChannelAutoConfigurationIntegrationTest}(webflux)와 동일한 패턴으로,
 * 전체 {@code KeycloakServletAutoConfiguration}(OAuth2 client/web security 등 무관한 필수 프로퍼티가
 * 많은 설정)이 아닌 인증(Authentication) 전용 nested {@code @Configuration}
 * ({@code KeycloakInfrastructureConfiguration} + {@code KeycloakAuthenticationConfiguration})만
 * 좁혀 등록합니다.</p>
 */
class KeycloakOidcJwtDecoderAutoConfigurationIntegrationTest {

  private static final String REALM_NAME = "test-realm";
  private static final String BASE_URL = "http://keycloak.local";
  private static final String RELATIVE_PATH = "";
  private static final String CLIENT_ID = "test-client";
  private static final String REDIRECT_URI = "{baseUrl}/login/oauth2/code/keycloak";
  private static final String LOGOUT_REDIRECT_URI = "http://localhost:8080";
  private static final String RESPONSE_TYPE = "code";
  private static final String CLIENT_SECRET = "test-secret";

  /**
   * {@code KeycloakSecurityProperties}({@code @ConfigurationProperties})를 활성화하기 위한 지원 설정.
   * {@code SessionConfigurationTest}의 {@code PropertyConfig}와 동일한 패턴.
   */
  @Configuration
  @EnableConfigurationProperties(KeycloakSecurityProperties.class)
  static class PropertiesConfig {
  }

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withUserConfiguration(PropertiesConfig.class)
      .withConfiguration(AutoConfigurations.of(
          KeycloakServletAutoConfiguration.KeycloakInfrastructureConfiguration.class,
          KeycloakServletAutoConfiguration.KeycloakAuthenticationConfiguration.class))
      .withPropertyValues(
          "keycloak.realm-name=" + REALM_NAME,
          "keycloak.base-url=" + BASE_URL,
          "keycloak.relative-path=" + RELATIVE_PATH,
          "keycloak.logout.redirect.uri=" + LOGOUT_REDIRECT_URI,
          "keycloak.response.type=" + RESPONSE_TYPE,
          "spring.security.oauth2.client.registration.keycloak.client-id=" + CLIENT_ID,
          "spring.security.oauth2.client.registration.keycloak.redirect-uri=" + REDIRECT_URI,
          "spring.security.oauth2.client.registration.keycloak.client-secret=" + CLIENT_SECRET);

  /**
   * {@code authenticationManager}({@link ProviderManager})가 실제로 배선한 {@link JwtDecoder}를
   * {@link KeycloakAuthenticationProvider}의 {@code jwtDecoder} 필드에서 꺼내옵니다.
   * {@code authenticationManager}가 바로 "이 decoder를 조립하는 지점"입니다.
   */
  private static JwtDecoder wiredOidcDecoder(AssertableApplicationContext context) {
    ProviderManager authenticationManager = (ProviderManager) context.getBean("authenticationManager");
    KeycloakAuthenticationProvider provider = authenticationManager.getProviders().stream()
        .filter(KeycloakAuthenticationProvider.class::isInstance)
        .map(KeycloakAuthenticationProvider.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "authenticationManager에 KeycloakAuthenticationProvider가 등록되어 있지 않습니다."));
    return (JwtDecoder) ReflectionTestUtils.getField(provider, "jwtDecoder");
  }

  // ==========================================================================
  // 무관 JwtDecoder 빈 공존 (name 기반 조건, 회귀 방지 CWE-347/863)
  // ==========================================================================

  @Nested
  @DisplayName("무관한 JwtDecoder 빈이 있어도 keycloakOidcJwtDecoder는 대체되지 않는다")
  class 무관_Decoder_대체_방지 {

    @Configuration
    static class UnrelatedResourceServerDecoderConfig {
      @Bean
      public JwtDecoder resourceServerJwtDecoder() {
        // 리소스서버용 등 무관한 decoder — 이름이 keycloakOidcJwtDecoder가 아니므로
        // 타입 기반 @ConditionalOnMissingBean(JwtDecoder.class)이었다면 우리 decoder가 생성되지
        // 않거나(조용히 대체), 두 빈이 동시에 존재해 NoUniqueBeanDefinitionException으로 기동
        // 자체가 실패했을 시나리오
        return mock(JwtDecoder.class);
      }
    }

    @Test
    @DisplayName("keycloakOidcJwtDecoder가 여전히 생성되고, authenticationManager는 그것만 주입받는다")
    void 무관_decoder_공존시_oidc_decoder_유지_및_authenticationManager_배선() {
      contextRunner
          .withUserConfiguration(UnrelatedResourceServerDecoderConfig.class)
          .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("keycloakOidcJwtDecoder");
            assertThat(context).hasBean("resourceServerJwtDecoder");
            assertThat(context.getBeansOfType(JwtDecoder.class)).hasSize(2);
            // 타입 기반 조건이었다면 여기서 NoUniqueBeanDefinitionException으로 기동이 실패했을 것
            assertThat(context).hasSingleBean(AuthenticationManager.class);

            JwtDecoder wiredDecoder = wiredOidcDecoder(context);

            assertThat(wiredDecoder)
                .isSameAs(context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("resourceServerJwtDecoder", JwtDecoder.class));
          });
    }
  }

  @Nested
  @DisplayName("여러 JwtDecoder(OIDC용 + 앱 decoder)가 공존해도 정확히 keycloakOidcJwtDecoder만 주입된다")
  class 다중_Decoder_공존 {

    @Configuration
    static class MultipleUnrelatedDecodersConfig {
      @Bean
      public JwtDecoder appJwtDecoder() {
        // 애플리케이션이 별도로 등록한 decoder (예: 리소스서버용)
        return mock(JwtDecoder.class);
      }

      @Bean
      public JwtDecoder anotherAppJwtDecoder() {
        // 또 다른 무관한 decoder
        return mock(JwtDecoder.class);
      }
    }

    @Test
    @DisplayName("총 3개의 JwtDecoder 빈이 공존하고, authenticationManager는 keycloakOidcJwtDecoder만 주입받는다")
    void 다중_decoder_공존시_정확히_oidc_decoder_주입() {
      contextRunner
          .withUserConfiguration(MultipleUnrelatedDecodersConfig.class)
          .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(JwtDecoder.class)).hasSize(3);

            JwtDecoder wiredDecoder = wiredOidcDecoder(context);

            assertThat(wiredDecoder)
                .isSameAs(context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("appJwtDecoder", JwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("anotherAppJwtDecoder", JwtDecoder.class));
          });
    }
  }

  // ==========================================================================
  // 이름 재정의 — 사용자가 keycloakOidcJwtDecoder 이름으로 직접 등록
  // ==========================================================================

  @Nested
  @DisplayName("사용자가 keycloakOidcJwtDecoder 이름으로 빈을 등록하면 라이브러리 기본 빈은 생략된다")
  class 이름_재정의 {

    @Configuration
    static class CustomOidcDecoderConfig {
      @Bean("keycloakOidcJwtDecoder")
      public JwtDecoder keycloakOidcJwtDecoder() {
        return mock(JwtDecoder.class);
      }
    }

    @Test
    @DisplayName("keycloakOidcJwtDecoder 빈이 사용자 정의로 대체되고, authenticationManager는 사용자 빈을 주입받는다")
    void 이름_재정의시_사용자_빈_사용_및_배선() {
      contextRunner
          .withUserConfiguration(CustomOidcDecoderConfig.class)
          .run(context -> {
            assertThat(context).hasNotFailed();
            // 이름이 같으므로 딱 하나만 존재 — 라이브러리 기본 빈(NimbusJwtDecoder)이 아니라
            // 사용자가 등록한 mock이어야 한다 (@ConditionalOnMissingBean(name=...)이 정상 작동)
            assertThat(context.getBeansOfType(JwtDecoder.class)).hasSize(1);

            JwtDecoder registeredDecoder = context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class);
            assertThat(mockingDetails(registeredDecoder).isMock()).isTrue();
            assertThat(registeredDecoder).isNotInstanceOf(NimbusJwtDecoder.class);

            JwtDecoder wiredDecoder = wiredOidcDecoder(context);
            assertThat(wiredDecoder).isSameAs(registeredDecoder);
          });
    }
  }

  // ==========================================================================
  // 기본(단독) 구성 — positive control
  // ==========================================================================

  @Nested
  @DisplayName("기본(단독) 구성에서 keycloakOidcJwtDecoder가 정상 생성된다")
  class 기본_단독_구성 {

    @Test
    @DisplayName("추가 설정 없이도 keycloakOidcJwtDecoder 빈이 정확히 하나 생성되고 authenticationManager에 주입된다")
    void 기본_구성시_decoder_정상_생성_및_배선() {
      contextRunner.run(context -> {
        assertThat(context).hasNotFailed();
        assertThat(context).hasSingleBean(JwtDecoder.class);
        assertThat(context).hasBean("keycloakOidcJwtDecoder");

        JwtDecoder decoder = context.getBean("keycloakOidcJwtDecoder", JwtDecoder.class);
        assertThat(decoder).isInstanceOf(NimbusJwtDecoder.class);

        JwtDecoder wiredDecoder = wiredOidcDecoder(context);
        assertThat(wiredDecoder).isSameAs(decoder);
      });
    }
  }
}
