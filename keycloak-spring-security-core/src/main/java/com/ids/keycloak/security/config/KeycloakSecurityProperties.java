package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Keycloak Security 관련 설정을 통합 관리하는 Root Properties 클래스입니다.
 * <p>
 * application.yaml 예시:
 * <pre>
 * keycloak:
 *   security:
 *     authentication:
 *       permit-all-paths:
 *         - /public/**
 *         - /health
 *     authorization:
 *       enabled: true
 *     logging:
 *       include-query-string: true
 *     cookie:
 *       http-only: true
 *       secure: true
 * </pre>
 * </p>
 */
@Getter
@ConfigurationProperties(prefix = "keycloak.security")
public class KeycloakSecurityProperties {

    /**
     * 인증(Authentication) 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakAuthenticationProperties authentication = new KeycloakAuthenticationProperties();

    /**
     * 인가(Authorization) 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakAuthorizationProperties authorization = new KeycloakAuthorizationProperties();

    /**
     * 쿠키 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakCookieProperties cookie = new KeycloakCookieProperties();

    /**
     * 에러 처리 관련 설정 (리다이렉트 URL 등)
     */
    @NestedConfigurationProperty
    private KeycloakErrorProperties error = new KeycloakErrorProperties();

    /**
     * Session 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakSessionProperties session = new KeycloakSessionProperties();

    /**
     * 로깅 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakLoggingProperties logging = new KeycloakLoggingProperties();

    /**
     * Basic Authentication 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakBasicAuthProperties basicAuth = new KeycloakBasicAuthProperties();

    /**
     * Bearer Token 인증 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakBearerTokenProperties bearerToken = new KeycloakBearerTokenProperties();

    /**
     * CSRF 보호 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakCsrfProperties csrf = new KeycloakCsrfProperties();

    /**
     * Rate Limiting 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakRateLimitProperties rateLimit = new KeycloakRateLimitProperties();

    /**
     * Keycloak {@code SecurityFilterChain}이 담당할 요청 경로 매처 설정.
     * <p>
     * 사용자가 자체 {@code SecurityFilterChain}(예: {@code /actuator} 전용)을 추가하더라도
     * Keycloak 체인이 함께 등록되어 담당 경로를 책임지도록 분리합니다. 기본값은 전체 경로({@code /**}).
     * </p>
     */
    @NestedConfigurationProperty
    private KeycloakMatcherProperties matcher = new KeycloakMatcherProperties();

    /**
     * Keycloak 기본 {@code SecurityFilterChain} 자동 등록 여부 (기본값: {@code true}).
     * <p>
     * {@code false}로 설정하면 Keycloak 기본 체인이 등록되지 않으며, 사용자가 전체
     * {@code SecurityFilterChain} 구성을 직접 책임집니다. (필요 시에만 명시적으로 opt-out)
     * </p>
     */
    @Setter
    private boolean autoFilterChain = true;

    /**
     * X-Forwarded-For 헤더에서 신뢰할 프록시 홉(hop) 수 (기본값: {@code 0}).
     *
     * <p>
     * <b>보안 설계:</b> XFF 헤더는 클라이언트가 임의로 위조할 수 있습니다.
     * 이 값으로 배포 환경의 신뢰 프록시 개수를 명시하면, XFF 오른쪽에서
     * 해당 홉 수만큼 건너뛴 IP를 실제 클라이언트 IP로 사용합니다.
     * </p>
     * <ul>
     *   <li>{@code 0} (기본값): XFF 헤더를 무시하고 TCP 연결 원격 주소({@code remoteAddr})를 사용합니다.
     *       <b>보안상 권장 기본값</b>입니다. (이전 동작인 XFF 첫 번째 IP 무조건 신뢰와 다릅니다)</li>
     *   <li>{@code 1}: 직접 연결된 프록시 1개 뒤의 IP를 신뢰합니다.
     *       예: {@code X-Forwarded-For: client, proxy1} 에서 {@code client}를 사용합니다.</li>
     *   <li>{@code N}: 우측에서 N번째 홉을 클라이언트 IP로 사용합니다.</li>
     * </ul>
     * <p>
     * <b>마이그레이션:</b> 기존 동작(XFF 첫 번째 무조건 신뢰)을 유지하고 싶다면
     * {@code keycloak.security.trusted-proxy-count=-1}로 설정하세요.
     * 단, 이는 보안상 위험하므로 권장하지 않습니다.
     * </p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     trusted-proxy-count: 1  # 리버스 프록시 1개 환경
     * </pre>
     */
    @Setter
    private int trustedProxyCount = 0;
}