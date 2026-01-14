package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak Security 인증(Authentication) 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     permit-all-paths:
 *       - /public/**
 *       - /health
 *       - /actuator/**
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakAuthenticationProperties {

    /**
     * 인증 없이 접근 가능한 경로 목록 (permitAll)
     * Ant 패턴 지원: /api/**, /public/*, etc.
     */
    private List<String> permitAllPaths = new ArrayList<>();
}
