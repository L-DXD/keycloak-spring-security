package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak {@code SecurityFilterChain}이 담당할 요청 경로를 정의하는 Properties 클래스입니다.
 * <p>
 * 사용자가 자체 {@code SecurityFilterChain}(예: {@code /actuator} 전용)을 추가하더라도
 * Keycloak 체인이 함께 등록되어 담당 경로를 책임지도록 {@code securityMatcher} 기반으로 경로를 분리합니다.
 * 기본값은 전체 경로({@code /**})이며, 사용자가 include/exclude로 재정의할 수 있습니다.
 * </p>
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     matcher:
 *       include:
 *         - /**
 *       exclude:
 *         - /actuator/**
 *         - /public/**
 * </pre>
 * </p>
 * <p>
 * RequestMatcher 변환은 spring-security-web 의존성이 있는 web-starter의 AutoConfiguration에서 수행합니다.
 * (core 모듈은 순수 로직 모듈로 Servlet/Web 의존성을 갖지 않습니다.)
 * </p>
 */
@Getter
@Setter
public class KeycloakMatcherProperties {

    /**
     * Keycloak 체인이 담당할 포함 경로 (Ant 패턴). 기본값: 전체 경로({@code /**}).
     */
    private List<String> include = new ArrayList<>(List.of("/**"));

    /**
     * Keycloak 체인에서 제외할 경로 (Ant 패턴). 제외된 경로는 사용자가 등록한 다른 체인이 담당합니다.
     */
    private List<String> exclude = new ArrayList<>();
}
