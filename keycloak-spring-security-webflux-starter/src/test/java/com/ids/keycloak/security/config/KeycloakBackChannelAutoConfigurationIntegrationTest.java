package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ids.keycloak.security.authentication.ReactiveOidcBackChannelLogoutHandler;
import com.ids.keycloak.security.filter.ReactiveBackChannelLogoutEndpointFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.session.ReactiveFindByIndexNameSessionRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * {@link KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration}의
 * 보안 Advisory 8 대응(name 기반 조건 + {@code @Qualifier} 배선 + client-id 필수화)을
 * {@link ApplicationContextRunner}로 검증하는 통합 테스트입니다.
 *
 * <p>{@code SessionConfigurationTest}와 동일한 패턴으로, 전체 {@code KeycloakWebFluxAutoConfiguration}
 * (OAuth2 client/web security 등 무관한 필수 프로퍼티가 많은 설정)이 아닌 Back-Channel 전용 nested
 * {@code @Configuration}만 좁혀 등록합니다.</p>
 */
class KeycloakBackChannelAutoConfigurationIntegrationTest {

  private static final String ISSUER_URI = "http://keycloak.local/realms/test";
  private static final String CLIENT_ID = "test-client";

  /**
   * 테스트용 combined 세션 저장소 인터페이스.
   * {@code ReactiveOidcBackChannelLogoutHandlerTest}의 {@code TestSessionRepository}와 동일한 패턴.
   */
  interface TestSessionRepository
      extends ReactiveFindByIndexNameSessionRepository<Session>, ReactiveSessionRepository<Session> {
  }

  /**
   * {@code @ConditionalOnBean(type = ReactiveFindByIndexNameSessionRepository)} 조건을 만족시키기
   * 위한 지원 설정. (Spring Session Reactive가 활성화된 상태를 흉내)
   */
  @Configuration
  static class SessionRepositoryConfig {
    @Bean
    public TestSessionRepository testSessionRepository() {
      return mock(TestSessionRepository.class);
    }
  }

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withUserConfiguration(SessionRepositoryConfig.class)
      .withConfiguration(AutoConfigurations.of(
          KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration.class))
      .withPropertyValues(
          "spring.security.oauth2.resourceserver.jwt.issuer-uri=" + ISSUER_URI,
          "spring.security.oauth2.client.registration.keycloak.client-id=" + CLIENT_ID);

  // ==========================================================================
  // 무관 decoder 대체 방지 (name 기반 조건, 회귀 방지 CWE-347/863)
  // ==========================================================================

  @Nested
  @DisplayName("무관한 ReactiveJwtDecoder 빈이 있어도 keycloakBackChannelJwtDecoder는 대체되지 않는다")
  class 무관_Decoder_대체_방지 {

    @Configuration
    static class UnrelatedResourceServerDecoderConfig {
      @Bean
      public ReactiveJwtDecoder resourceServerJwtDecoder() {
        // 리소스서버용 등 무관한 decoder — 이름이 keycloakBackChannelJwtDecoder가 아니므로
        // 타입 기반 @ConditionalOnMissingBean이었다면 우리 decoder를 밀어냈을 시나리오
        return mock(ReactiveJwtDecoder.class);
      }
    }

    @Test
    @DisplayName("keycloakBackChannelJwtDecoder가 여전히 생성되고, 핸들러는 그것만 @Qualifier로 주입받는다")
    void 무관_decoder_공존시_backchannel_decoder_유지_및_핸들러_배선() {
      contextRunner
          .withUserConfiguration(UnrelatedResourceServerDecoderConfig.class)
          .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("keycloakBackChannelJwtDecoder");
            assertThat(context).hasBean("resourceServerJwtDecoder");
            assertThat(context.getBeansOfType(ReactiveJwtDecoder.class)).hasSize(2);

            ReactiveOidcBackChannelLogoutHandler handler =
                context.getBean(ReactiveOidcBackChannelLogoutHandler.class);
            Object wiredDecoder = ReflectionTestUtils.getField(handler, "jwtDecoder");

            assertThat(wiredDecoder)
                .isSameAs(context.getBean("keycloakBackChannelJwtDecoder", ReactiveJwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("resourceServerJwtDecoder", ReactiveJwtDecoder.class));

            // 필터도 정상적으로 이 핸들러로 배선되어야 한다
            assertThat(context).hasSingleBean(ReactiveBackChannelLogoutEndpointFilter.class);
          });
    }
  }

  // ==========================================================================
  // 다중 ReactiveJwtDecoder 공존
  // ==========================================================================

  @Nested
  @DisplayName("여러 ReactiveJwtDecoder(OIDC용 + 앱 decoder + 백채널)가 공존해도 정확히 백채널 decoder만 주입된다")
  class 다중_Decoder_공존 {

    @Configuration
    static class MultipleUnrelatedDecodersConfig {
      @Bean
      public ReactiveJwtDecoder keycloakOidcReactiveJwtDecoder() {
        // OIDC 쿠키 로그인용 decoder (실제 오토컨피규레이션의 빈 이름을 흉내)
        return mock(ReactiveJwtDecoder.class);
      }

      @Bean
      public ReactiveJwtDecoder appReactiveJwtDecoder() {
        // 애플리케이션이 별도로 등록한 decoder (예: 리소스서버용)
        return mock(ReactiveJwtDecoder.class);
      }
    }

    @Test
    @DisplayName("총 3개의 ReactiveJwtDecoder 빈이 공존하고, 핸들러는 keycloakBackChannelJwtDecoder만 주입받는다")
    void 다중_decoder_공존시_정확히_backchannel_decoder_주입() {
      contextRunner
          .withUserConfiguration(MultipleUnrelatedDecodersConfig.class)
          .run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(ReactiveJwtDecoder.class)).hasSize(3);

            ReactiveOidcBackChannelLogoutHandler handler =
                context.getBean(ReactiveOidcBackChannelLogoutHandler.class);
            Object wiredDecoder = ReflectionTestUtils.getField(handler, "jwtDecoder");

            assertThat(wiredDecoder)
                .isSameAs(context.getBean("keycloakBackChannelJwtDecoder", ReactiveJwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("keycloakOidcReactiveJwtDecoder", ReactiveJwtDecoder.class));
            assertThat(wiredDecoder)
                .isNotSameAs(context.getBean("appReactiveJwtDecoder", ReactiveJwtDecoder.class));
          });
    }
  }

  // ==========================================================================
  // client-id 누락/공백 → 기동 실패
  // ==========================================================================

  @Nested
  @DisplayName("client-id가 없거나 공백이면 Back-Channel 설정이 기동에 실패한다")
  class ClientId_누락시_기동_실패 {

    @Test
    @DisplayName("client-id 프로퍼티 자체가 없으면 IllegalStateException으로 기동 실패")
    void client_id_미설정시_기동_실패() {
      new ApplicationContextRunner()
          .withUserConfiguration(SessionRepositoryConfig.class)
          .withConfiguration(AutoConfigurations.of(
              KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration.class))
          .withPropertyValues("spring.security.oauth2.resourceserver.jwt.issuer-uri=" + ISSUER_URI)
          .run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                .hasRootCauseInstanceOf(IllegalStateException.class);
            assertThat(context.getStartupFailure())
                .rootCause()
                .hasMessageContaining("client-id")
                .hasMessageContaining("Advisory 8");
          });
    }

    @Test
    @DisplayName("client-id가 공백 문자열이면 IllegalStateException으로 기동 실패")
    void client_id_공백시_기동_실패() {
      new ApplicationContextRunner()
          .withUserConfiguration(SessionRepositoryConfig.class)
          .withConfiguration(AutoConfigurations.of(
              KeycloakWebFluxAutoConfiguration.KeycloakBackChannelLogoutConfiguration.class))
          .withPropertyValues(
              "spring.security.oauth2.resourceserver.jwt.issuer-uri=" + ISSUER_URI,
              "spring.security.oauth2.client.registration.keycloak.client-id=   ")
          .run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                .hasRootCauseInstanceOf(IllegalStateException.class);
            assertThat(context.getStartupFailure())
                .rootCause()
                .hasMessageContaining("client-id");
          });
    }

    @Test
    @DisplayName("정상 설정(issuer-uri + client-id)이면 기동이 성공한다 (positive control)")
    void 정상_설정시_기동_성공() {
      contextRunner.run(context -> assertThat(context).hasNotFailed());
    }
  }
}
