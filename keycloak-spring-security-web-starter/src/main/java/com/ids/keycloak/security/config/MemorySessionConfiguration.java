package com.ids.keycloak.security.config;

import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

/**
 * In-Memory 세션 저장소 설정.
 * <p>
 * keycloak.session.store-type=memory (기본값) 일 때 활성화됩니다.
 * 단일 인스턴스 환경에 적합합니다.
 * </p>
 * <p>
 * <b>운영 배포 안내:</b> 이 저장소는 JVM 힙 기반이며 인스턴스 재시작 시 세션이
 * 소실되고, 다중 인스턴스 간에 세션이 공유되지 않습니다. {@code maxSessions}
 * (기본값 10,000)와 스케줄 정리로 무한 메모리 증가는 방지하지만, 인터넷에
 * 노출되는 운영 배포에서는 {@code keycloak.security.session.store-type=redis}로
 * 전환하여 {@link RedisSessionConfiguration}을 사용하는 것을 권장합니다.
 * </p>
 * <p>
 * <b>잔여 트레이드오프(login-availability):</b> {@code maxSessions} 상한에 도달하면
 * OOM을 막기 위해 신규 세션(신규 로그인 개시 포함)이 fail-closed로 거부될 수 있습니다.
 * 이미 인증된 기존 세션은 상한과 무관하게 계속 유지되며, {@code timeout}이 지난 세션은
 * 스케줄 정리로 자동 회수되어 시간이 지나면 상한에 다시 여유가 생깁니다. 인터넷에
 * 노출되는 운영 환경에서는 Redis 전환에 더해 OIDC 로그인 개시 엔드포인트에 대한
 * 별도의 rate limit을 함께 적용해 이 트레이드오프를 보완하는 것을 권장합니다. 자세한
 * 내용은 {@link IndexedMapSessionRepository}의 클래스 Javadoc을 참고하십시오.
 * </p>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "keycloak.security.session", name = "store-type", havingValue = "memory", matchIfMissing = true)
@EnableSpringHttpSession
@Slf4j
public class MemorySessionConfiguration {

    public MemorySessionConfiguration() {
        log.info("Keycloak Session: In-Memory 세션 저장소가 활성화되었습니다.");
    }

    /**
     * Principal Name으로 세션을 검색할 수 있는 In-Memory 세션 저장소 Bean.
     * 백채널 로그아웃 기능을 위해 FindByIndexNameSessionRepository 인터페이스를 구현합니다.
     *
     * @param properties Keycloak 보안 프로퍼티
     */
    @Bean
    @ConditionalOnMissingBean(FindByIndexNameSessionRepository.class)
    public FindByIndexNameSessionRepository<MapSession> sessionRepository(KeycloakSecurityProperties properties) {
        KeycloakSessionProperties sessionProperties = properties.getSession();
        IndexedMapSessionRepository repository = new IndexedMapSessionRepository(
            new ConcurrentHashMap<>(),
            sessionProperties.getMaxSessions(),
            sessionProperties.getCleanupInterval());
        repository.setDefaultMaxInactiveInterval(sessionProperties.getTimeout());
        log.info("Keycloak Session: In-Memory 세션 만료 시간이 {}초, 최대 세션 수가 {}개, "
                + "정리 스케줄 주기가 {}초로 설정되었습니다.",
            sessionProperties.getTimeout().toSeconds(),
            sessionProperties.getMaxSessions(),
            sessionProperties.getCleanupInterval().toSeconds());
        return repository;
    }
}
