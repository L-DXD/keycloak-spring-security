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

    /**
     * 오설정으로 인한 Medium #4(CWE-352) 재현을 막기 위한 기동 시 검증입니다.
     *
     * <p>Bearer Token 전용 로그아웃 경로는 {@code prefix + "/logout"}로 계산되어 CSRF 면제
     * 목록에 추가됩니다. 이때 {@code prefix}가 공백이거나 {@code "/"}이면 계산된 경로가 브라우저
     * Front-Channel 로그아웃 경로({@code /logout})와 같아지거나(빈 문자열) 컨테이너의 중복 슬래시
     * 정규화로 인해 사실상 같은 경로로 취급되어("/" + "/logout" = "//logout"), 브라우저 폼 기반
     * {@code /logout}까지 CSRF 검증 없이 호출 가능해집니다 — 즉 Medium #4로 막았던 강제
     * 로그아웃 CSRF(CWE-352)가 다시 열립니다. 이를 조용히 허용하지 않고 기동 실패로 즉시
     * 드러냅니다.</p>
     *
     * @throws IllegalStateException prefix가 공백이거나, {@code "/"}로 시작하지 않거나, {@code "/"} 그
     *     자체인 경우
     */
    public void validate() {
        if (prefix == null || prefix.isBlank()) {
            throw new IllegalStateException(
                "keycloak.security.bearer-token.token-endpoint.prefix: 공백일 수 없습니다 (prefix="
                    + prefix + "). prefix가 공백이면 Bearer 전용 로그아웃 경로(prefix + \"/logout\")가 "
                    + "브라우저 Front-Channel 로그아웃 경로(\"/logout\")와 동일해져, 브라우저 폼 기반 "
                    + "/logout까지 CSRF 검증 없이 호출 가능해집니다(Medium #4 무력화, CWE-352).");
        }

        if (!prefix.startsWith("/") || prefix.equals("/")) {
            throw new IllegalStateException(
                "keycloak.security.bearer-token.token-endpoint.prefix: \"/\"로 시작하되 \"/\" 그 "
                    + "자체는 아니어야 합니다 (prefix=\"" + prefix + "\"). prefix가 \"/\"이면 Bearer "
                    + "전용 로그아웃 경로가 \"//logout\"이 되어, 컨테이너/프록시의 중복 슬래시 정규화에 "
                    + "따라 브라우저 Front-Channel 로그아웃 경로(\"/logout\")와 사실상 동일하게 취급될 "
                    + "수 있습니다(Medium #4 무력화, CWE-352).");
        }
    }
}
