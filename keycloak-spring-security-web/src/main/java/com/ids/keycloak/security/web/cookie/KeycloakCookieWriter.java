package com.ids.keycloak.security.web.cookie;

import java.time.Duration;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 쿠키 읽기·쓰기·지우기 (확장 지점). 기본은 {@link DefaultKeycloakCookieWriter}:
 * {@code __Host-{앱 이름}_*}, Secure, HttpOnly, SameSite=Lax, Path=/, Domain 없음.
 * 쿠키 이름 규칙이나 속성을 바꾸려면 이 빈을 바꾸거나 기본 구현을 상속한다.
 */
public interface KeycloakCookieWriter {

    /** 쿠키 이름. 예: {@code __Host-demo_sid}. */
    String name(KeycloakCookie cookie);

    /** 요청의 쿠키 값. 없거나 비었으면 빈 값. */
    Optional<String> read(HttpServletRequest request, KeycloakCookie cookie);

    /**
     * 쿠키를 쓴다. {@code maxAge}가 1초보다 짧으면 지운다.
     *
     * @param maxAge 수명. 초 아래는 버린다 (만료 시각보다 늦게 남지 않게)
     */
    void write(HttpServletResponse response, KeycloakCookie cookie, String value, Duration maxAge);

    /** 쿠키를 지운다 (같은 이름·속성·Path, Max-Age=0). */
    void clear(HttpServletResponse response, KeycloakCookie cookie);

    /** 네 쿠키를 모두 지운다 (로그아웃·로컬 로그아웃, COOKIE-04). */
    default void clearAll(HttpServletResponse response) {
        for (KeycloakCookie cookie : KeycloakCookie.values()) {
            clear(response, cookie);
        }
    }
}
