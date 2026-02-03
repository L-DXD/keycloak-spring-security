package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * 비동기 처리 시 SecurityContext 전파 및 스레드 풀 관련 설정입니다.
 * <p>
 * StreamingResponseBody, @Async, CompletableFuture 등 비동기 처리 환경에서
 * 부모 스레드의 SecurityContext(인증 정보)를 자식 스레드로 전파하기 위한 설정을 제공합니다.
 * </p>
 *
 * <h3>스레드 풀 설정 가이드</h3>
 * <p>
 * 기본값은 일반적인 웹 애플리케이션의 I/O 작업을 가정하여 설정되어 있습니다.
 * 실제 운영 환경에서는 수행되는 작업의 성격(CPU 집약적 vs I/O 집약적)과 하드웨어 리소스에 맞춰
 * 튜닝하는 것을 권장합니다.
 * </p>
 *
 * <pre>
 * keycloak:
 *  security:
 *      async:
 *          security-context-propagation: true
 *          core-pool-size: 20  # (CPU Core * 2) + 여유분
 *          max-pool-size: 100
 *          queue-capacity: 200
 * </pre>
 */
@Getter
@Setter
public class KeycloakAsyncProperties {

    /**
     * 비동기 처리 시 SecurityContext 전파 활성화 여부.
     * <p>
     * <b>true</b>로 설정하면 {@link org.springframework.scheduling.annotation.Async} 메서드나
     * 별도의 스레드에서 실행되는 로직에서도 {@code SecurityContextHolder.getContext().getAuthentication()}을
     * 통해 인증 정보를 조회할 수 있습니다.
     * </p>
     * 기본값: false
     */
    private boolean securityContextPropagation = false;

    /**
     * 스레드 풀의 기본 크기 (Core Pool Size).
     * <p>
     * 스레드 풀이 생성될 때 초기에 생성되는 스레드 개수이며, 유휴 상태에서도 유지되는 최소 스레드 수입니다.
     * </p>
     *
     * <b>설정 가이드:</b>
     * <ul>
     * <li><b>I/O 집약적 작업</b> (DB 조회, 외부 API 호출 등):
     * 대기 시간이 길기 때문에 코어 수보다 넉넉하게 설정 권장.
     * <br/><i>권장 공식: CPU Core 수 * (1 + 대기시간/서비스시간)</i>
     * </li>
     * <li><b>CPU 집약적 작업</b> (복잡한 연산, 암호화 등):
     * 컨텍스트 스위칭 비용을 줄이기 위해 CPU Core 수 + 1 정도로 설정 권장.
     * </li>
     * </ul>
     * 기본값: 10 (일반적인 소규모 I/O 처리를 가정)
     */
    private int corePoolSize = 10;

    /**
     * 스레드 풀의 최대 크기 (Max Pool Size).
     * <p>
     * 큐(Queue)가 가득 찼을 때, 추가로 확장 가능한 최대 스레드 개수입니다.
     * 트래픽 폭주 시 시스템의 안정성을 해치지 않는 선에서 설정해야 합니다.
     * </p>
     * <b>주의:</b> 너무 높게 설정할 경우 잦은 컨텍스트 스위칭(Context Switching)으로 인해 오히려 성능이 저하될 수 있습니다.
     * <br/>
     * 기본값: 50
     */
    private int maxPoolSize = 50;

    /**
     * 작업 대기열의 최대 크기 (Queue Capacity).
     * <p>
     * 모든 Core 스레드가 사용 중일 때, 작업을 대기시키는 큐의 크기입니다.
     * </p>
     * <b>동작 방식:</b>
     * <ol>
     * <li>Core 스레드가 꽉 차면 큐에 작업을 쌓음</li>
     * <li>큐까지 꽉 차면 Max 스레드까지 스레드를 추가 생성</li>
     * <li>Max 스레드까지 꽉 차면 요청 거절 (RejectedExecutionException)</li>
     * </ol>
     * 기본값: 100
     */
    private int queueCapacity = 100;

    /**
     * 생성되는 스레드의 이름 접두사.
     * <p>
     * 로그 및 모니터링 시 스레드를 식별하기 위해 사용됩니다.
     * </p>
     * 기본값: "keycloak-async-"
     */
    private String threadNamePrefix = "keycloak-async-";
}