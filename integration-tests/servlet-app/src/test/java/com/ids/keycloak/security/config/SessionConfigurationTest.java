package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.session.MapSession;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.FindByIndexNameSessionRepository;

/**
 * 세션 저장소 설정(Memory/Redis)이 프로퍼티에 따라 올바르게 로드되는지 검증합니다.
 */
class SessionConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            KeycloakServletAutoConfiguration.class,
            MemorySessionConfiguration.class,
            RedisSessionConfiguration.class
        ));

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
                assertThat(context).hasSingleBean(FindByIndexNameSessionRepository.class);
                assertThat(context.getBean(FindByIndexNameSessionRepository.class))
                    .isInstanceOf(RedisIndexedSessionRepository.class);

                // Memory 관련 설정은 로드되지 않아야 함
                assertThat(context).doesNotHaveBean(IndexedMapSessionRepository.class);
            });
    }

    @Test
    @DisplayName("store-type=redis여도 RedisConnectionFactory가 없으면 설정이 로드되지 않아야 한다")
    void redisConfigRequiresConnectionFactory() {
        contextRunner
            .withPropertyValues("keycloak.session.store-type=redis")
            .run(context -> {
                // RedisConnectionFactory가 없으면 RedisSessionConfiguration의 @ConditionalOnClass/Bean 조건 불만족
                // 따라서 세션 리포지토리 빈이 생성되지 않거나 에러가 날 수 있음.
                // 하지만 여기서는 AutoConfiguration이 동작하지 않아서 빈이 없는 상태를 확인
                assertThat(context).doesNotHaveBean(RedisIndexedSessionRepository.class);
                
                // Memory 설정도 redis 프로퍼티 때문에 스킵됨 -> 세션 저장소 빈이 아예 없어야 함
                assertThat(context).doesNotHaveBean(FindByIndexNameSessionRepository.class);
            });
    }
}
