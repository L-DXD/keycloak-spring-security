package com.ids.keycloak.security.web.csrf;

import java.time.Duration;
import java.util.Objects;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.cookie.KeycloakCookie;
import com.ids.keycloak.security.web.cookie.KeycloakCookieWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * CSRF 토큰 저장소 (V3-10, 01 설계 4-7): sid에 서명으로 묶은 double-submit 토큰. 토큰 원본은 {@code __Host-{앱}_csrf} 쿠키(HttpOnly)에 두고,
 * 화면은 {@code GET /api/csrf}로 받은 값(Spring 기본 Xor 처리기가 요청마다 가린 값)을 헤더 {@value #HEADER_NAME} 또는 폼 칸
 * {@value #PARAMETER_NAME}에 넣어 보낸다.
 * <ul>
 *   <li>쿠키의 토큰은 이 요청의 sid 쿠키로 서명이 맞을 때만 쓴다. 다른 사람의 csrf 쿠키를 심어도 통하지 않는다(CSRF-04)</li>
 *   <li>로그인하면 sid가 바뀌고 로그인 처리기가 새 토큰을 쓰므로 예전 토큰은 통하지 않는다(CSRF-06)</li>
 *   <li>로그인 전(sid 쿠키 없음)에는 빈 값에 묶은 토큰을 준다. 로그인 전 상태 바꾸는 요청(공개 폼 등)도 같은 방식으로 막는다</li>
 * </ul>
 * 세션 행은 보지 않는다(요청마다 DB를 부르지 않는다).
 */
public class SignedDoubleSubmitCsrfTokenRepository implements CsrfTokenRepository {

    /** 화면이 토큰을 넣어 보내는 헤더. */
    public static final String HEADER_NAME = "X-XSRF-TOKEN";
    /** HTML 폼이 토큰을 넣어 보내는 숨은 칸. */
    public static final String PARAMETER_NAME = "_csrf";
    /** 로그인 전 토큰을 묶는 값. */
    protected static final String ANONYMOUS = "";

    private final KeycloakCsrfTokenSigner signer;
    private final KeycloakCookieWriter cookies;
    private final Duration cookieMaxAge;

    /**
     * @param cookieMaxAge 여기서 새로 만든 토큰의 쿠키 수명(보통 절대 상한). 로그인 때의 쿠키는 로그인 처리기가 sid와 같은 수명으로 쓴다
     */
    public SignedDoubleSubmitCsrfTokenRepository(KeycloakCsrfTokenSigner signer, KeycloakCookieWriter cookies, Duration cookieMaxAge) {
        this.signer = Objects.requireNonNull(signer);
        this.cookies = Objects.requireNonNull(cookies);
        this.cookieMaxAge = Objects.requireNonNull(cookieMaxAge);
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return token(signer.create(binding(request)));
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null) {
            cookies.clear(response, KeycloakCookie.CSRF);
        } else {
            cookies.write(response, KeycloakCookie.CSRF, token.getToken(), cookieMaxAge);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        String binding = binding(request);
        return cookies.read(request, KeycloakCookie.CSRF)
            .filter(value -> signer.matches(binding, value))
            .map(this::token)
            .orElse(null);
    }

    /** 토큰을 묶는 값: sid 쿠키(모양이 맞을 때), 없으면 {@link #ANONYMOUS}. */
    protected String binding(HttpServletRequest request) {
        return cookies.read(request, KeycloakCookie.SESSION).filter(SessionIds::looksLikeSid).orElse(ANONYMOUS);
    }

    protected CsrfToken token(String value) {
        return new DefaultCsrfToken(HEADER_NAME, PARAMETER_NAME, value);
    }
}
