package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak Security 에러 처리 관련 설정을 담는 Properties 클래스입니다.
 * <p>
 * application.yaml:
 * <pre>
 * keycloak:
 *   security:
 *     error:
 *       redirect-enabled: true  # true면 리다이렉트 (풀스택), false면 JSON 응답 (API)
 *       ajax-returns-json: true  # AJAX 요청은 리다이렉트 대신 JSON 응답
 *       authentication-failed-redirect-url: /login  # 인증 실패 시 리다이렉트
 *       session-expired-redirect-url: /login?expired=true  # 세션 만료 시 리다이렉트
 *       access-denied-redirect-url: /error/403  # 접근 거부 시 리다이렉트
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakErrorProperties {

    /**
     * 에러 발생 시 리다이렉트 활성화 여부
     * true: 리다이렉트 (풀스택 모드)
     * false: JSON 응답 (API 모드) - 기본값
     */
    private boolean redirectEnabled = false;

    /**
     * AJAX 요청 시 JSON 응답 반환 여부 (redirectEnabled가 true일 때만 유효)
     * true: AJAX 요청(X-Requested-With: XMLHttpRequest 또는 Accept: application/json)은 JSON 응답
     * false: 모든 요청에 리다이렉트 - 기본값
     */
    private boolean ajaxReturnsJson = false;

    /**
     * 인증 실패 시 리다이렉트할 URL (redirectEnabled가 true일 때 사용)
     * 기본값: "/login"
     */
    private String authenticationFailedRedirectUrl = "/login";

    /**
     * 세션 만료 시 리다이렉트할 URL (redirectEnabled가 true일 때 사용)
     * 설정하지 않으면 authenticationFailedRedirectUrl 사용
     * 기본값: null (authenticationFailedRedirectUrl 사용)
     */
    private String sessionExpiredRedirectUrl;

    /**
     * 접근 거부(403) 시 리다이렉트할 URL (redirectEnabled가 true일 때 사용)
     * 기본값: "/error/403"
     */
    private String accessDeniedRedirectUrl = "/error/403";

    /**
     * (C-1 회귀 수정) {@code redirectEnabled=false}(API 모드, 기본값) 상태에서, 브라우저의
     * HTML 네비게이션 요청(비-AJAX, {@code Accept: text/html} 등)에 대해 OAuth2 로그인
     * authorization endpoint({@code /oauth2/authorization/{registrationId}})로 자동
     * 리다이렉트할지 여부입니다 (기본값: {@code true}).
     * <p>
     * <b>배경:</b> {@code exceptionHandling}에 이 라이브러리의 EntryPoint를 등록하면, Spring
     * Security {@code oauth2Login}이 기본적으로 제공하던 "미인증 브라우저 요청 → 로그인 페이지(authorization
     * endpoint) 리다이렉트" 동작이 완전히 가려진다. {@code redirectEnabled}의 기본값이 {@code false}이므로,
     * 이 프로퍼티가 없다면 풀스택(서버 렌더링) 소비자의 모든 미인증 브라우저 요청이 401 JSON을 받게 되어
     * SSO 로그인 진입 자체가 불가능해진다(치명적 회귀). 이 프로퍼티는 정확히 그 기본 동작을 복원한다.
     * </p>
     * <p>
     * AJAX/JSON 요청({@code SecurityHandlerUtil#isAjaxRequest})과 Basic Auth 요청은 이 리다이렉트
     * 대상이 아니며 기존과 동일하게 401 JSON(또는 WWW-Authenticate 헤더 포함 401)을 받는다. API 전용
     * 소비자로서 이 자동 위임이 필요 없다면 {@code false}로 꺼서 항상 401 JSON을 받도록 할 수 있다.
     * {@code redirectEnabled=true}로 커스텀 리다이렉트 플로우를 이미 명시적으로 구성한 소비자에게는
     * 이 프로퍼티가 적용되지 않는다(기존 커스텀 설정이 우선).
     * </p>
     *
     * <pre>
     * keycloak:
     *   security:
     *     error:
     *       oauth2-login-redirect-enabled: false  # 순수 API 서버: 항상 401 JSON
     * </pre>
     */
    private boolean oauth2LoginRedirectEnabled = true;

    /**
     * {@link #oauth2LoginRedirectEnabled}가 적용될 때 리다이렉트할 OAuth2 Client
     * {@code registrationId}입니다 (기본값: {@code "keycloak"}).
     * <p>
     * 이 라이브러리는 단일 {@code ClientRegistration}("keycloak")만 지원하므로 기본값을 그대로 사용하면
     * 충분하다. 소비자가 registrationId를 다르게 등록한 경우에만 재정의한다.
     * </p>
     */
    private String oauth2LoginRegistrationId = "keycloak";

    /**
     * 세션 만료 시 리다이렉트할 URL을 반환합니다.
     * sessionExpiredRedirectUrl이 설정되지 않은 경우 authenticationFailedRedirectUrl을 반환합니다.
     */
    public String getEffectiveSessionExpiredRedirectUrl() {
        return sessionExpiredRedirectUrl != null ? sessionExpiredRedirectUrl : authenticationFailedRedirectUrl;
    }
}
