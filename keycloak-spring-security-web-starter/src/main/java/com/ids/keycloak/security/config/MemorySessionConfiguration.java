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
     */
    @Bean
    @ConditionalOnMissingBean(FindByIndexNameSessionRepository.class)
    public FindByIndexNameSessionRepository<MapSession> sessionRepository() {
        log.debug("IndexedMapSessionRepository (In-Memory with Principal Name Index) 생성");
        return new IndexedMapSessionRepository(new ConcurrentHashMap<>());
    }
}
