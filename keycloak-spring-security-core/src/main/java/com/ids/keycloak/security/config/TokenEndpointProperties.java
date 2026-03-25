package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Bearer Token 토큰 발급 엔드포인트 관련 설정입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     bearer-token:
 *       token-endpoint:
 *         prefix: /auth    # 기본값: /auth
 * </pre>
 * </p>
 */
@Getter
@Setter
public class TokenEndpointProperties {

    /**
     * 토큰 발급 API 엔드포인트 prefix.
     * 기본값: /auth
     * <p>
     * 실제 엔드포인트:
     * <ul>
     *   <li>POST {prefix}/token — 토큰 발급</li>
     *   <li>POST {prefix}/refresh — 토큰 갱신</li>
     *   <li>POST {prefix}/logout — 로그아웃</li>
     * </ul>
     * </p>
     */
    private String prefix = "/auth";
}
