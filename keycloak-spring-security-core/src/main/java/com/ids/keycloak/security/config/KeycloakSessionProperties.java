package com.ids.keycloak.security.config;

import java.time.Duration;
import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak 세션 저장소 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml 예시:
 * <pre>
 * keycloak:
 *   security:
 *      session:
 *          store-type: memory  # 또는 redis
 *          timeout: 30m        # 세션 만료 시간 (기본값: 30분)
 * </pre>
 * </p>
 * <p>
 * <b>운영 배포 안내:</b> {@code store-type: memory}는 단일 인스턴스·개발 환경에 적합한
 * 임시 저장소입니다. {@code maxSessions}로 상한을 두더라도 JVM 힙 내부 자료구조이므로
 * 인스턴스 재시작 시 세션이 모두 소실되고, 다중 인스턴스 환경에서는 세션이 공유되지
 * 않습니다. 인터넷에 노출되는 운영 환경에서는 {@code store-type: redis}로 전환하여
 * 외부의 상한·TTL이 있는 저장소(Redis 등)를 사용하는 것을 권장합니다.
 * </p>
 */
@Getter
@Setter
public class KeycloakSessionProperties {

    /**
     * 세션 저장소 유형 (MEMORY 또는 REDIS)
     * 기본값: MEMORY (하위 호환성 유지)
     */
    private SessionStoreType storeType = SessionStoreType.MEMORY;

    /**
     * 세션 만료 시간.
     * 기본값: 30분
     */
    private Duration timeout = Duration.ofMinutes(30);

    /**
     * (memory 저장소 전용) 저장소가 동시에 유지할 수 있는 최대 세션 수.
     * <p>
     * <b>보안 설계(CWE-400/CWE-770 방어):</b> 세션 쿠키를 보관하지 않고 OIDC 로그인을
     * 반복 개시하면 버려진 익명 세션이 무한정 쌓여 메모리를 고갈시킬 수 있습니다.
     * 상한에 도달하면 아직 추적되지 않은 신규 세션은 <b>fail-closed</b>(저장 거부)로
     * 처리되고, 이미 저장된 세션은 상한과 무관하게 정상적으로 갱신·조회됩니다.
     * (Rate Limiting의 {@code maxTrackedKeys}와 동일한 정책입니다.)
     * </p>
     * <p>0 이하로 설정해도 기본값으로 대체됩니다(무제한 비허용).</p>
     * 기본값: 10,000
     */
    private int maxSessions = 10_000;

    /**
     * (memory 저장소 전용) 만료된 세션을 스캔해 제거하는 정리 스케줄 주기.
     * <p>
     * 애플리케이션의 {@code @EnableScheduling} 설정에 의존하지 않고, 저장소 내부의
     * 전용 데몬 스레드에서 이 주기로 실행됩니다. 라이브러리가 호스트 애플리케이션의
     * 스케줄링 인프라(예: 잠들어 있던 다른 {@code @Scheduled} 메서드)에 의도치 않게
     * 영향을 주지 않기 위한 설계입니다.
     * </p>
     * 기본값: 5분
     */
    private Duration cleanupInterval = Duration.ofMinutes(5);
}
