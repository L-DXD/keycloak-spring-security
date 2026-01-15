package com.ids.keycloak.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

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
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "keycloak.security.session", name = "store-type", havingValue = "redis")
@ConditionalOnClass(name = {
    "org.springframework.data.redis.connection.RedisConnectionFactory",
    "org.springframework.session.data.redis.RedisIndexedSessionRepository"
})
@AutoConfigureAfter(name = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@EnableRedisHttpSession(redisNamespace = "${spring.session.redis.namespace:${spring.application.name:spring:session}}")
@Slf4j
public class RedisSessionConfiguration {

    /**
     * @EnableRedisHttpSession이 RedisIndexedSessionRepository를 자동으로 Bean 등록합니다.
     * RedisIndexedSessionRepository는 FindByIndexNameSessionRepository<Session>을 구현하므로
     * 백채널 로그아웃 기능이 그대로 동작합니다.
     */
    public RedisSessionConfiguration() {
        log.info("Keycloak Session: Redis 세션 저장소가 활성화되었습니다.");
    }
}
