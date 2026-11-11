package com.ids.keycloak.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 검증을 통과한 액세스 토큰 → 인증 (확장 지점, 01 설계 4-3). 기본은 {@link DefaultKeycloakPrincipalConverter}(권한 없음).
 * <p>
 * 역할을 권한으로 바꾸거나 앱 사용자 테이블을 읽으려면 이 타입의 빈을 올린다. 돌려준 인증이 그대로 컨트롤러에 들어간다.
 * {@link AuthenticationException}을 던지면 그 요청만 로그인 안 한 것으로 본다(세션은 그대로 둔다).
 * 요청마다 불리므로 느린 일(원격 호출)은 앱이 캐시한다.
 */
@FunctionalInterface
public interface KeycloakPrincipalConverter {

    Authentication convert(Jwt accessToken);
}
