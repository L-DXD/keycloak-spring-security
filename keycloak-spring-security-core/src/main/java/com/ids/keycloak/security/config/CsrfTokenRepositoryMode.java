package com.ids.keycloak.security.config;

/**
 * CSRF 토큰을 어디에 저장·조회할지 선택하는 열거형입니다.
 *
 * <p><b>배경(요구사항 4번):</b> {@code keycloak.security.matcher.exclude}로 제외한 경로는
 * Keycloak {@code SecurityFilterChain} 자체가 적용되지 않으므로(자세한 내용은
 * {@link KeycloakMatcherProperties#getExclude()} Javadoc 참고) 그 경로에서는 {@code CsrfFilter}도
 * 동작하지 않는다. 기본 저장소인 {@link #SESSION}({@code HttpSessionCsrfTokenRepository})은 CSRF
 * 토큰을 서버 측 HTTP Session에만 보관하므로, exclude된 경로(체인 밖)에서 렌더링되는 폼(예: 별도
 * 체인이 서비스하는 로그아웃 유사 폼)은 애초에 CSRF 토큰을 세션에 심을 기회가 없어 hidden input을
 * 채우지 못하고, 이후 그 폼이 Keycloak 체인이 담당하는 경로로 제출되면 CSRF 검증에 실패한다.</p>
 *
 * <p>{@link #COOKIE}({@code CookieCsrfTokenRepository})를 사용하면 토큰이 브라우저 쿠키에 저장되어
 * exclude된 경로에서도(체인이 적용되지 않아도) 이미 발급된 토큰 쿠키를 그대로 읽어 폼에 반영하거나
 * 이후 요청 헤더에 실어 보낼 수 있다. matcher.exclude를 사용하면서 그 경로에서 CSRF 토큰이 필요한
 * 경우에만 {@link #COOKIE}로 전환하면 된다.</p>
 *
 * <pre>
 * keycloak:
 *   security:
 *     csrf:
 *       token-repository: COOKIE
 * </pre>
 */
public enum CsrfTokenRepositoryMode {

    /**
     * {@code HttpSessionCsrfTokenRepository}(servlet) /
     * {@code WebSessionServerCsrfTokenRepository}(webflux)를 사용합니다. <b>기본값(기존 동작
     * 유지)</b>입니다. CSRF 토큰을 서버 측 세션에만 저장하므로,
     * {@code keycloak.security.matcher.exclude}로 제외된 경로(체인 밖, {@code CsrfFilter} 미적용)에서는
     * 토큰을 읽거나 심을 수 없습니다.
     */
    SESSION,

    /**
     * {@code CookieCsrfTokenRepository.withHttpOnlyFalse()}(servlet) /
     * {@code CookieServerCsrfTokenRepository.withHttpOnlyFalse()}(webflux)를 사용합니다. CSRF
     * 토큰을 브라우저 쿠키에 저장하므로, {@code keycloak.security.matcher.exclude}로 제외된 경로에서도
     * 이미 발급된 토큰 쿠키를 읽어 폼(hidden input)이나 요청 헤더에 반영할 수 있습니다. 쿠키는
     * JavaScript로 읽을 수 있어야 CSRF 헤더에 실어 보낼 수 있으므로 {@code HttpOnly=false}로
     * 발급합니다(CSRF 토큰 자체는 세션 쿠키와 달리 노출되어도 무해하다는 것이 Spring Security의
     * 표준 권고입니다).
     */
    COOKIE
}
