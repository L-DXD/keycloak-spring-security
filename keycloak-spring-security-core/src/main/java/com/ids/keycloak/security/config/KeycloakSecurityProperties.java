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
     * Session 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakSessionProperties session = new KeycloakSessionProperties();

    /**
     * 로깅 관련 설정
     */
    @NestedConfigurationProperty
    private KeycloakLoggingProperties logging = new KeycloakLoggingProperties();

}