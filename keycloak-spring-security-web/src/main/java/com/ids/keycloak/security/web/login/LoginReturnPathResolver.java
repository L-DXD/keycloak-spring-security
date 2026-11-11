package com.ids.keycloak.security.web.login;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 로그인 뒤 돌아갈 화면 경로 (확장 지점). 로그인 시작 요청에서 정하고, 로그인 임시 쿠키에 담았다가 성공하면 화면 주소 뒤에 붙인다.
 * 기본은 {@link DefaultLoginReturnPathResolver} ({@code return} 파라미터, 상대 경로만).
 */
@FunctionalInterface
public interface LoginReturnPathResolver {

    /**
     * @return {@code /}로 시작하는 상대 경로. 받을 수 없는 값이면 {@code /}
     */
    String resolve(HttpServletRequest request);
}
