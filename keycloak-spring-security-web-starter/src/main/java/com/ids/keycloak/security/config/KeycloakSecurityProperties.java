package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak Security 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml 예시:
 * <pre>
 * keycloak:
 *   security:
 *     permit-all-paths:
 *       - /public/**
 *       - /health
 *       - /actuator/**
 *     authorization-enabled: true
 * </pre>
 * </p>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak.security")
public class KeycloakSecurityProperties {

    /**
     * 인증 없이 접근 가능한 경로 목록 (permitAll)
     * Ant 패턴 지원: /api/**, /public/*, etc.
     */
    private List<String> permitAllPaths = new ArrayList<>();

    /**
     * Keycloak Authorization Services 사용 여부.
     * true: 매 요청마다 Keycloak에 인가 요청 (Policy Enforcement)
     * false: Spring Security 기본 인가 사용 (authenticated만 확인)
     */
    private boolean authorizationEnabled = false;
}
