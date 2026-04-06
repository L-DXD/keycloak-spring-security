package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 * CSRF(Cross-Site Request Forgery) 보호 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     csrf:
 *       enabled: true                     # 기본값: true (기존 동작 유지)
 *       ignore-paths:                     # 추가 CSRF 면제 경로
 *         - /api/**
 *         - /webhook/**
 * </pre>
 * </p>
 * <p>
 * CSRF는 보안상 기본 활성화(true)입니다.
 * 비활성화하려면 명시적으로 {@code enabled: false}를 설정해야 합니다.
 * </p>
 * <p>
 * {@code ignore-paths}는 기존 하드코딩된 면제 경로(로그아웃, 토큰 발급 등)에 추가로 적용됩니다.
 * Ant 패턴을 지원합니다 (예: {@code /api/**}).
 * </p>
 */
@Getter
@Setter
public class KeycloakCsrfProperties {

    /**
     * CSRF 보호 활성화 여부.
     * 기본값: true (보안상 기본 활성화, 다른 Properties의 기본값 false와 다름)
     */
    private boolean enabled = true;

    /**
     * 추가 CSRF 면제 경로 목록.
     * Ant 패턴을 지원합니다 (예: /api/**, /webhook/**).
     * 기존 하드코딩 면제 경로(로그아웃, 토큰 발급 등)에 추가로 적용됩니다.
     */
    private List<String> ignorePaths = new ArrayList<>();
}
