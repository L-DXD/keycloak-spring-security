package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Rate Limiting 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     rate-limit:
 *       enabled: true                    # 기본값: false (opt-in)
 *       max-requests: 5                  # 시간 윈도우 내 최대 요청 수
 *       window-seconds: 60              # 시간 윈도우 (초)
 *       block-duration-seconds: 300     # 차단 지속 시간 (초), 0이면 윈도우와 동일
 *       key-strategy: IP_AND_USERNAME   # IP, USERNAME, IP_AND_USERNAME
 *       include-basic-auth: true        # Basic Auth에도 적용 (기본값: true)
 *       max-tracked-keys: 100000        # 인메모리 카운터 맵 최대 추적 키 수
 * </pre>
 * </p>
 * <p>
 * Rate Limiting이 활성화되면 토큰 발급 API({@code /auth/token})와 Basic Auth 요청에 대해
 * 브루트포스 공격을 방지하기 위한 요청 제한이 적용됩니다.
 * </p>
 */
@Getter
@Setter
public class KeycloakRateLimitProperties {

    /**
     * Rate Limiting 활성화 여부.
     * 기본값: false (opt-in 방식)
     */
    private boolean enabled = false;

    /**
     * 시간 윈도우 내 최대 요청 수.
     * 기본값: 5
     */
    private int maxRequests = 5;

    /**
     * 시간 윈도우 (초).
     * 기본값: 60
     */
    private long windowSeconds = 60;

    /**
     * 차단 지속 시간 (초).
     * 0이면 윈도우와 동일하게 적용됩니다.
     * 기본값: 300 (5분)
     */
    private long blockDurationSeconds = 300;

    /**
     * Rate Limiting 키 전략.
     * 기본값: IP_AND_USERNAME
     */
    private RateLimitKeyStrategy keyStrategy = RateLimitKeyStrategy.IP_AND_USERNAME;

    /**
     * Basic Auth 요청에도 Rate Limiting을 적용할지 여부.
     * 기본값: true
     */
    private boolean includeBasicAuth = true;

    /**
     * 인메모리 Rate Limiter가 동시에 추적할 수 있는 최대 키(IP/username) 수.
     * <p>
     * <b>보안 설계:</b> XFF 등으로 매 요청마다 새로운 키(IP)를 생성하는 카디널리티 공격은
     * 메모리를 무한히 소비시킬 수 있습니다(CWE-400). 이 값을 초과하면 새 키에 대한
     * 요청은 <b>fail-closed</b>(즉시 차단)로 처리되어 메모리 상한을 보장합니다.
     * 기존에 추적 중인 키는 계속 정상적으로 판단됩니다.
     * </p>
     * 기본값: 100,000
     */
    private int maxTrackedKeys = 100_000;
}
