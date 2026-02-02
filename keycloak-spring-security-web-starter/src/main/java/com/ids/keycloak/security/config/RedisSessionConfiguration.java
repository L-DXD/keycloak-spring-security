package com.ids.keycloak.security.config;

import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;

/**
 * Redis 세션 저장소 설정.
 * <p>
 * keycloak.session.store-type=redis 일 때 활성화됩니다.
 * 다중 인스턴스 환경 및 세션 영속성이 필요한 경우 사용합니다.
 * </p>
 * <p>
 * 이 설정은 Spring Boot의 RedisAutoConfiguration에 의해 구성된
 * RedisConnectionFactory를 사용합니다. 따라서 Redis 연결 설정은
 * spring.data.redis.* 프로퍼티로 관리합니다.
 * </p>
 *
 * <h3>사용자 프로젝트 의존성 요구사항</h3>
 * <pre>
 * dependencies {
 *     implementation 'org.springframework.boot:spring-boot-starter-data-redis'
 *     implementation 'org.springframework.session:spring-session-data-redis'
 * }
 * </pre>
 *
 * <h3>세션 만료 시간 설정</h3>
 * <pre>
 * keycloak:
 *   security:
 *     session:
 *       store-type: redis
 *       timeout: 1h  # 세션 만료 시간 (기본값: 30m)
 * </pre>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "keycloak.security.session", name = "store-type", havingValue = "redis")
@ConditionalOnClass(name = {
    "org.springframework.data.redis.connection.RedisConnectionFactory",
    "org.springframework.session.data.redis.RedisIndexedSessionRepository"
})
@AutoConfigureAfter(name = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@AutoConfigureBefore(name = "org.springframework.boot.autoconfigure.session.SessionAutoConfiguration")
@EnableRedisIndexedHttpSession
@Slf4j
public class RedisSessionConfiguration {

    /**
     * Redis namespace 설정.
     * spring.session.redis.namespace 프로퍼티를 사용하며, 없으면 기본값 사용.
     */
    @Value("${spring.session.redis.namespace:${spring.application.name:spring:session}}")
    private String redisNamespace;

    /**
     * 세션 저장소의 기본 만료 시간을 설정합니다.
     * keycloak.security.session.timeout 프로퍼티 값을 사용합니다.
     * @EnableRedisHttpSession의 maxInactiveIntervalInSeconds 속성은 상수여야 하므로
     * 동적 설정을 위해 SessionRepositoryCustomizer를 사용합니다.
     */
    @Bean
    public org.springframework.session.config.SessionRepositoryCustomizer<org.springframework.session.data.redis.RedisIndexedSessionRepository> springSessionRepositoryCustomizer(KeycloakSecurityProperties properties) {
        return repository -> {
            Duration timeout = properties.getSession().getTimeout();
            repository.setDefaultMaxInactiveInterval(timeout);

            if (redisNamespace != null && !redisNamespace.isBlank()) {
                repository.setRedisKeyNamespace(redisNamespace);
            }

            log.info("Keycloak Session: Redis 세션 저장소가 활성화되었습니다. (만료 시간: {}초, Namespace: {})",
                timeout.toSeconds(), redisNamespace);
        };
    }
}
