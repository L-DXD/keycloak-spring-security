package com.ids.keycloak.security.event;

/**
 * 세션 이벤트를 받는다 (확장 지점). 기본은 {@link KeycloakSessionAuditLogger}(감사 로그).
 * 감사 테이블에 저장하려면 이것을 구현해 빈으로 올린다. 그러면 기본 감사 로그는 꺼진다.
 * <p>
 * 리스너가 예외를 던져도 로그인·갱신·로그아웃은 그대로 진행한다.
 */
@FunctionalInterface
public interface KeycloakSessionEventListener {

    void onSessionEvent(KeycloakSessionEvent event);
}
