package com.ids.keycloak.security.token;

/**
 * 액세스 토큰(at 쿠키)을 로컬에서 검증한다. Keycloak을 부르지 않는다 (JWKS만 받아 둔다).
 * <p>
 * 확장 지점: 같은 타입의 빈을 올리면 그것을 쓴다. 규칙을 더할 때는 {@link DefaultKeycloakAccessTokenValidator}를 상속하거나 감싼다.
 */
@FunctionalInterface
public interface KeycloakAccessTokenValidator {

    /**
     * @param token at 쿠키 값 (JWT 문자열)
     * @return 결과. 예외를 던지지 않는다
     */
    AccessTokenValidationResult validate(String token);
}
