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
     * <p>
     * <b>주의(요구사항 4번):</b> 이 값은 {@code securityMatcher}에 사용되어 <b>SecurityFilterChain
     * 자체가 적용되지 않게</b> 만듭니다. 인증(Authentication)만 빠지는 것이 아니라, 이 라이브러리가
     * 이 체인에 등록하는 CSRF 보호({@code CsrfFilter}), 예외 처리({@code ExceptionTranslationFilter}
     * + Keycloak EntryPoint/AccessDeniedHandler), MDC 로깅 필터, Rate Limit 필터 등이 <b>전부</b>
     * 미적용됩니다. 그 경로는 사용자가 등록한 다른 {@code SecurityFilterChain}(또는 체인 밖)이 전적으로
     * 책임집니다.
     * </p>
     * <p>
     * "인증만" 제외하고 싶다면(즉 이 체인의 CSRF/MDC/예외 처리는 그대로 유지한 채 해당 경로만
     * 인증 없이 접근을 허용하려면) 이 값이 아니라
     * {@code keycloak.security.authentication.permit-all-paths}를 사용하세요. permit-all-paths는
     * {@code authorizeHttpRequests}에서만 해당 경로를 permitAll로 허용할 뿐, 체인 자체(CSRF 필터 등)는
     * 그대로 적용된 채 유지됩니다.
     * </p>
     */
    private List<String> exclude = new ArrayList<>();
}
