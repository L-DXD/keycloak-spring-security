package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Bearer Token 인증 관련 설정입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     bearer-token:
 *       enabled: true                    # 기본값: false (opt-in)
 *       token-endpoint:
 *         prefix: /auth                  # 기본값: /auth
 * </pre>
 * </p>
 * <p>
 * 토큰 검증은 Keycloak Introspect API(RFC 7662) 기반 온라인 검증만 지원합니다.
 * </p>
 */
@Getter
@Setter
public class KeycloakBearerTokenProperties {

    /**
     * Bearer Token 인증 활성화 여부.
     * 기본값: false (opt-in)
     */
    private boolean enabled = false;

    /**
     * 토큰 발급 엔드포인트 설정
     */
    @NestedConfigurationProperty
    private TokenEndpointProperties tokenEndpoint = new TokenEndpointProperties();
}
