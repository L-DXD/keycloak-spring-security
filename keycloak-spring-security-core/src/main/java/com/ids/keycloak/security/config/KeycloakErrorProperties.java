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
     * 세션 만료 시 리다이렉트할 URL을 반환합니다.
     * sessionExpiredRedirectUrl이 설정되지 않은 경우 authenticationFailedRedirectUrl을 반환합니다.
     */
    public String getEffectiveSessionExpiredRedirectUrl() {
        return sessionExpiredRedirectUrl != null ? sessionExpiredRedirectUrl : authenticationFailedRedirectUrl;
    }
}
