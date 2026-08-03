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
     * <p>
     * <b>잔여 트레이드오프(login-availability):</b> 이 상한은 메모리 무한 증가(OOM)를
     * 막기 위한 것이며, 상한 도달 시 신규 세션 생성(신규 로그인 개시 포함)이 일시적으로
     * 거부될 수 있다는 가용성 저하를 대가로 합니다. 이미 인증된 기존 세션은 영향받지
     * 않고, {@code timeout} 경과분은 {@code cleanupInterval} 스케줄에 의해 자동 회수되어
     * 상한에 다시 여유가 생깁니다. 인터넷에 노출되는 운영 환경에서는 {@code store-type:
     * redis} 전환과 더불어 OIDC 로그인 개시 엔드포인트에 대한 별도의 rate limit을 함께
     * 적용해 이 트레이드오프를 보완하는 것을 권장합니다.
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

    /**
     * Back-Channel 로그아웃이 실질적으로 동작할 수 없는 상태(indexed session repository 부재)일 때
     * 애플리케이션 기동을 실패시킬지 여부 (기본값: {@code false}).
     * <p>
     * <b>배경(항목 7):</b> Back-Channel 로그아웃은 {@code FindByIndexNameSessionRepository}(servlet)
     * / {@code ReactiveFindByIndexNameSessionRepository}(webflux) 구현체가 있어야 세션을 principal
     * 기준으로 찾아 무효화할 수 있습니다. 기본 {@code store-type: memory}는 이 인터페이스를 구현하지
     * 않으므로, 이 저장소를 쓰는 대부분의 소비자에게는 Back-Channel 로그아웃이 겉보기에는 설정되어도
     * 실제로는 세션을 무효화하지 못합니다.
     * <ul>
     *   <li>servlet: Keycloak의 back-channel logout 요청에 200을 반환하지만 세션은 그대로 남습니다
     *       (silent no-op).</li>
     *   <li>webflux: 관련 빈 자체가 조건부로 등록되지 않아 엔드포인트가 404를 반환합니다.</li>
     * </ul>
     * <b>기본값(false)에서의 동작:</b> 기동 시 WARN 로그로 원인과 해결 방법(indexed session repository
     * 구성 또는 이 옵션 인지)을 안내하되, 기동은 계속 진행합니다(memory 세션 기본값 환경이 다수이므로
     * 무조건 예외로 막는 것은 과할 수 있음).
     * </p>
     * <p>
     * <b>{@code true}로 설정 시:</b> Back-Channel 로그아웃을 반드시 사용해야 하는 배포(예: 강제
     * 로그아웃이 컴플라이언스 요구사항인 경우)에서, indexed session repository 없이 기동되는 것을
     * {@code IllegalStateException}으로 즉시 막습니다.
     * </p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     session:
     *       back-channel-logout-strict: true
     * </pre>
     */
    private boolean backChannelLogoutStrict = false;

    /**
     * (redis 저장소 전용) 손상된 세션을 감지했을 때 Redis 키를 실제로 삭제할지 여부
     * (기본값: {@code false}).
     * <p>
     * <b>배경(M-C, M-6 후속):</b> Redis 세션 폴백 매퍼는 손상된 세션을 감지하면 미인증(재로그인
     * 유도)으로 처리한다 — 이 동작 자체는 항상 안전하며 이 옵션과 무관하게 유지된다. 문제는 M-6에서
     * catch 범위를 {@code RuntimeException} 전체로 넓히면서, 이 매퍼가 감지한 모든 손상 세션의
     * Redis 키를 곧바로 삭제하도록 되어 있었다는 점이다. 롤링 배포 중 인스턴스마다 클래스(직렬화
     * 포맷)가 다른 상태에서, 신버전 인스턴스가 구버전이 쓴 <b>정상 세션</b>을 읽다가
     * {@code SerializationException}을 만나면 이를 "손상"으로 오인해 삭제해버려, 배포 도중 다수의
     * 정상 사용자가 전체 강제 로그아웃되는 운영 사고 위험이 있었다.
     * </p>
     * <p>
     * <b>기본값({@code false})에서의 동작:</b> 손상 세션은 여전히 미인증으로 처리되어 HTTP 500은
     * 발생하지 않지만, Redis 키 자체는 삭제하지 않는다(세션은 {@code timeout} 경과 후 Redis TTL로
     * 자연 만료된다). {@code true}로 설정하면 감지 즉시 키를 삭제한다 — 배포 파이프라인이 롤링
     * 배포 중 일시적 직렬화 불일치를 겪지 않는다고 확신하는 환경에서만 켜라.
     * </p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     session:
     *       cleanup-corrupted: false
     * </pre>
     */
    private boolean cleanupCorrupted = false;
}
