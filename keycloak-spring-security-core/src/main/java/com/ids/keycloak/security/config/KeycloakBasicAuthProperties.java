package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Basic Authentication 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     basic-auth:
 *       enabled: true  # 기본값: false (opt-in)
 * </pre>
 * </p>
 * <p>
 * Basic Auth가 활성화되면 {@code Authorization: Basic} 헤더를 통한 인증이
 * 기존 OIDC 쿠키 인증과 병렬로 동작합니다.
 * Keycloak의 Direct Access Grants (Resource Owner Password Credentials)를 통해
 * username/password를 토큰으로 교환하여 인증합니다.
 * </p>
 * <p>
 * <b>보안 경고:</b> HTTP Basic Auth는 브라우저에 노출될 경우 CSRF에 취약할 수 있습니다.
 * 브라우저는 사용자가 한 번 입력한 Basic 자격증명을 origin 단위로 캐시하여 이후의 모든 요청
 * (공격자가 만든 cross-origin 폼 제출 포함)에 자동으로 재전송합니다. 이 라이브러리는 더 이상
 * {@code Authorization: Basic} 헤더 보유만으로 CSRF를 면제하지 않으므로, 브라우저에서 접근
 * 가능한 경로는 Basic Auth 사용 여부와 무관하게 CSRF 토큰이 필요합니다. Basic Auth는 curl,
 * 서버-to-서버 호출 등 브라우저가 개입하지 않는 머신 클라이언트 전용으로 사용하는 것을 권장하며,
 * 그런 API 경로만 {@link KeycloakCsrfProperties#getIgnorePaths()}에 명시적으로 등록하세요.
 * </p>
 */
@Getter
@Setter
public class KeycloakBasicAuthProperties {

    /**
     * Basic Authentication 활성화 여부.
     * 기본값: false (opt-in 방식)
     */
    private boolean enabled = false;
}
