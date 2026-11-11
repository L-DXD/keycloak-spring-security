package com.ids.keycloak.security.event;

/**
 * 세션 이벤트를 내보낸다. 라이브러리 안쪽(로그인·갱신·로그아웃·정리 작업)이 부른다.
 * 기본 구현은 {@link CompositeKeycloakSessionEventPublisher}.
 */
@FunctionalInterface
public interface KeycloakSessionEventPublisher {

    void publish(KeycloakSessionEvent event);

    /** 아무 것도 하지 않는다. */
    static KeycloakSessionEventPublisher noop() {
        return event -> {
        };
    }
}
