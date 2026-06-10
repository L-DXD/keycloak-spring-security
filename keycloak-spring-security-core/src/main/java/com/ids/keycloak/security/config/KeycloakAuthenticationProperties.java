package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak Security 인증(Authentication) 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     authentication:
 *       permit-all-paths:
 *         - /public/**
 *         - /health
 *       default-success-url: /home
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

    /**
     * 로그인 성공 후 리다이렉트할 기본 URL
     * 기본값: "/"
     */
    private String defaultSuccessUrl = "/";

    /**
     * Credential(body) 기반 로그인 요청으로 판별할 경로 목록.
     * POST 메서드 + 이 목록에 포함된 경로이면 CREDENTIAL_LOGIN으로 분류하여 OIDC 필터를 우회합니다.
     * <p>
     * application.yaml:
     * <pre>
     * keycloak:
     *   security:
     *     authentication:
     *       login-paths:
     *         - /api/keycloak/login
     *         - /api/auth/login
     * </pre>
     * </p>
     */
    private List<String> loginPaths = new ArrayList<>(List.of("/api/keycloak/login"));

    /**
     * OIDC authorize 요청에 추가할 파라미터 설정.
     * <p>
     * acr_values, max_age, prompt 파라미터를 제어합니다.
     * 모든 필드의 기본값은 null이므로 미설정 시 기존 authorize 요청과 동일하게 동작합니다.
     * </p>
     * <p>
     * application.yaml:
     * <pre>
     * keycloak:
     *   security:
     *     authentication:
     *       authorization-request:
     *         acr-values: "gold"
     *         max-age: 3600
     *         prompt: "login"
     * </pre>
     * </p>
     */
    @NestedConfigurationProperty
    private KeycloakAuthorizationRequestProperties authorizationRequest =
        new KeycloakAuthorizationRequestProperties();

    /**
     * UserInfo 엔드포인트 호출 실패 시 인증 실패로 처리할지 여부 (기본값: {@code false}).
     *
     * <p>
     * <b>기본 동작(false):</b> UserInfo 엔드포인트 호출 실패 시 빈 권한으로 인증을 성공합니다.
     * 기존 동작과 동일하며 회귀가 없습니다.
     * </p>
     * <p>
     * <b>true로 설정 시:</b> UserInfo 호출 실패(네트워크 오류 포함)를 인증 실패로 승격합니다.
     * Keycloak UserInfo 엔드포인트가 안정적으로 운영되는 환경에서 보안을 강화하려면
     * {@code true}로 설정하세요.
     * </p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     authentication:
     *       require-user-info: true  # UserInfo 실패를 인증 실패로 처리
     * </pre>
     */
    private boolean requireUserInfo = false;
}
