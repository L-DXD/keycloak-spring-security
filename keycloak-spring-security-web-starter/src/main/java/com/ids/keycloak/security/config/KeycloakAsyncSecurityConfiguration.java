package com.ids.keycloak.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 비동기 처리 시 SecurityContext 전파를 위한 자동 설정입니다.
 * <p>
 * {@code keycloak.security.async.security-context-propagation=true}로 설정하면
 * StreamingResponseBody, DeferredResult 등 비동기 처리에서 SecurityContext가 자동으로 전파됩니다.
 * </p>
 *
 * <h3>사용 예시</h3>
 * <pre>
 * # application.yaml
 * keycloak:
 *   security:
 *     async:
 *       security-context-propagation: true
 *       core-pool-size: 10
 *       max-pool-size: 50
 * </pre>
 *
 * <h3>이 설정이 해결하는 문제</h3>
 * <pre>
 * // StreamingResponseBody 내부에서 SecurityContext 사용 가능
 * {@literal @}GetMapping("/download")
 * public StreamingResponseBody download() {
 *     return outputStream -> {
 *         // 이 설정이 없으면 null, 있으면 정상 동작
 *         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 *         // ...
 *     };
 * }
 * </pre>
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(
    prefix = "keycloak.security.async",
    name = "security-context-propagation",
    havingValue = "true"
)
public class KeycloakAsyncSecurityConfiguration implements WebMvcConfigurer {

    private final KeycloakSecurityProperties securityProperties;

    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        KeycloakAsyncProperties asyncProperties = securityProperties.getAsync();

        log.info("Keycloak Async Security: SecurityContext 전파가 활성화되었습니다. " +
            "[corePoolSize={}, maxPoolSize={}, queueCapacity={}]",
            asyncProperties.getCorePoolSize(),
            asyncProperties.getMaxPoolSize(),
            asyncProperties.getQueueCapacity());

        // ThreadPoolTaskExecutor 생성
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(asyncProperties.getCorePoolSize());
        executor.setMaxPoolSize(asyncProperties.getMaxPoolSize());
        executor.setQueueCapacity(asyncProperties.getQueueCapacity());
        executor.setThreadNamePrefix(asyncProperties.getThreadNamePrefix());
        executor.initialize();

        // SecurityContext를 전파하는 Executor로 래핑
        DelegatingSecurityContextAsyncTaskExecutor securityExecutor =
            new DelegatingSecurityContextAsyncTaskExecutor(executor);

        configurer.setTaskExecutor(securityExecutor);

        log.debug("Keycloak Async Security: DelegatingSecurityContextAsyncTaskExecutor 설정 완료");
    }
}
