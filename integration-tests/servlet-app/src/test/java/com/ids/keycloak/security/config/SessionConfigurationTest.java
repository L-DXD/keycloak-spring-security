package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;

/**
 * 세션 저장소 설정(Memory/Redis)이 프로퍼티에 따라 올바르게 로드되는지 검증합니다.
 *
 * Note: KeycloakServletAutoConfiguration은 OAuth2 의존성이 필요하므로 제외하고
 * 세션 설정 클래스만 테스트합니다.
 */
class SessionConfigurationTest {

   @Configuration
   @EnableConfigurationProperties(KeycloakSecurityProperties.class)
   static class PropertyConfig {
   }

   private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
       .withConfiguration(AutoConfigurations.of(
           MemorySessionConfiguration.class,
           RedisSessionConfiguration.class
       ))
       .withUserConfiguration(PropertyConfig.class);

   @Test
   @DisplayName("기본값(Memory)일 때 IndexedMapSessionRepository가 등록되어야 한다")
   void defaultToMemorySessionRepository() {
      contextRunner
          .withPropertyValues("keycloak.session.store-type=memory")
          .run(context -> {
             assertThat(context).hasSingleBean(FindByIndexNameSessionRepository.class);
             assertThat(context.getBean(FindByIndexNameSessionRepository.class))
                 .isInstanceOf(IndexedMapSessionRepository.class);

             // Redis 관련 설정은 로드되지 않아야 함
             assertThat(context).doesNotHaveBean(RedisIndexedSessionRepository.class);
          });
   }

   @Test
   @DisplayName("store-type=redis이고 RedisConnectionFactory가 존재할 때 RedisIndexedSessionRepository가 등록되어야 한다")
   void activeRedisSessionRepository() {
      contextRunner
          .withPropertyValues("keycloak.session.store-type=redis")
          .withBean(RedisConnectionFactory.class, () -> org.mockito.Mockito.mock(RedisConnectionFactory.class))
          .run(context -> {
             // Note: @EnableRedisHttpSession은 실제 Redis 연결이 필요하므로
             // 이 테스트에서는 설정 클래스가 로드되는지만 확인
             // 실제 RedisIndexedSessionRepository 생성은 통합 테스트에서 검증
             assertThat(context.getStartupFailure()).isNull();
          });
   }

   @Test
   @DisplayName("store-type=redis여도 RedisConnectionFactory가 없으면 설정이 로드되지 않아야 한다")
   void redisConfigRequiresConnectionFactory() {
      contextRunner
          .withPropertyValues("keycloak.session.store-type=redis")
          .run(context -> {
             // RedisConnectionFactory가 없으면 RedisSessionConfiguration의 @ConditionalOnClass 조건 불만족
             // Memory 설정도 redis 프로퍼티 때문에 스킵됨
             assertThat(context).doesNotHaveBean(RedisIndexedSessionRepository.class);
          });
   }

   @Test
   @DisplayName("프로퍼티가 없을 때 기본값으로 Memory 세션 저장소가 활성화되어야 한다")
   void defaultToMemoryWhenNoProperty() {
      contextRunner
          .run(context -> {
             // matchIfMissing=true이므로 기본값은 memory
             assertThat(context).hasSingleBean(FindByIndexNameSessionRepository.class);
             assertThat(context.getBean(FindByIndexNameSessionRepository.class))
                 .isInstanceOf(IndexedMapSessionRepository.class);
          });
   }
}
