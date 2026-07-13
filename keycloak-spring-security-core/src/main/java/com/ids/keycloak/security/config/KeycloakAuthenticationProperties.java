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

    /**
     * OIDC ID/Access Token 서명 검증에 사용할 issuer({@code iss}) URI를 명시적으로 지정합니다
     * (기본값: 미설정, {@code null}).
     *
     * <p><b>보안 Advisory 1(High #1) 관련 — 반드시 실제 토큰의 iss(발급자, 브라우저에 노출되는 Keycloak
     * 공개 URL/frontendUrl)와 정확히 일치해야 합니다.</b> {@code keycloak.base-url}은 이 라이브러리가
     * Keycloak API를 서버간 호출할 때 쓰는 URL로, 내부 네트워크 주소나 {@code /etc/hosts} 매핑 호스트일 수
     * 있어 브라우저가 보는 공개 URL과 다를 수 있습니다. 이 프로퍼티 없이 base-url이 공개 URL과 다르면
     * {@code JwtIssuerValidator}의 exact-match 검증이 모든 요청에서 실패해 <b>OIDC 쿠키 로그인이 전면
     * 장애</b>가 됩니다.</p>
     *
     * <p>미설정 시 해석 우선순위: 1) 이 프로퍼티 → 2) 표준 Spring Boot 프로퍼티
     * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} 또는
     * {@code spring.security.oauth2.client.provider.keycloak.issuer-uri}(Back-Channel 로그아웃 검증 및
     * {@code oauth2Login}의 {@code ClientRegistration}과 동일 원천 — 설정해두면 자동으로 issuer가
     * 통일됨) → 3) {@code keycloak.base-url} + {@code relative-path} + {@code realm-name}으로부터
     * 파생(레거시 기본 동작, base-url이 공개 URL과 같은 단순 환경에서만 안전).</p>
     *
     * <p>{@link com.ids.keycloak.security.util.KeycloakIssuerUriResolver#resolveEffectiveIssuerUri}
     * 가 이 우선순위를 구현합니다.</p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     authentication:
     *       issuer-uri: https://sso.example.com/realms/myrealm
     * </pre>
     */
    private String issuerUri;
}
