package com.ids.keycloak.security.event;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 리스너 여러 개에 차례로 보낸다. 리스너 하나가 예외를 던져도 나머지에 보내고, 부른 쪽에는 예외를 넘기지 않는다.
 */
public class CompositeKeycloakSessionEventPublisher implements KeycloakSessionEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(CompositeKeycloakSessionEventPublisher.class);

    private final List<KeycloakSessionEventListener> listeners;

    public CompositeKeycloakSessionEventPublisher(List<? extends KeycloakSessionEventListener> listeners) {
        this.listeners = List.copyOf(listeners);
    }

    @Override
    public void publish(KeycloakSessionEvent event) {
        for (KeycloakSessionEventListener listener : listeners) {
            try {
                listener.onSessionEvent(event);
            } catch (RuntimeException e) {
                log.warn("[KSS] 세션 이벤트 리스너가 실패했습니다 (계속 진행): type={}, listener={}", event.type(),
                    listener.getClass().getName(), e);
            }
        }
    }
}
