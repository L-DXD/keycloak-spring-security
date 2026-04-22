package com.ids.keycloak.security.authentication;

/**
 * HTTP 요청에서 감지된 인증 방식을 나타내는 열거형입니다.
 * <p>
 * {@link AuthenticationMethodDetector}가 요청을 분석하여 이 값을 반환합니다.
 * {@code KeycloakAuthenticationFilter}는 이 값에 따라 처리 경로를 분기합니다.
 * </p>
 */
public enum AuthenticationMethod {

    /**
     * {@code Authorization: Bearer <token>} 헤더가 있는 요청.
     * BearerTokenAuthenticationFilter가 처리하므로 KeycloakAuthenticationFilter는 pass-through.
     */
    BEARER,

    /**
     * {@code Authorization: Basic <credentials>} 헤더가 있는 요청.
     * BasicAuthenticationFilter가 처리하므로 KeycloakAuthenticationFilter는 pass-through.
     */
    BASIC,

    /**
     * POST 메서드 + 설정된 login-paths 경로에 해당하는 자격증명 기반 로그인 요청.
     * 컨트롤러(Resource Owner Password 등)가 처리하므로 KeycloakAuthenticationFilter는 pass-through.
     */
    CREDENTIAL_LOGIN,

    /**
     * {@code access_token} 또는 {@code id_token} 쿠키가 존재하는 요청.
     * KeycloakAuthenticationFilter가 OIDC 쿠키 기반 인증을 수행합니다.
     */
    OIDC_COOKIE,

    /**
     * 위 어느 방식에도 해당하지 않는 요청 (익명/미인증 상태).
     * 예외를 발생시키지 않고 pass-through합니다.
     */
    NONE
}
