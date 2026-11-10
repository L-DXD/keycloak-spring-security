package com.ids.keycloak.security.sample.e2e;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.PayloadApplicationEvent;

import com.ids.keycloak.security.event.KeycloakSessionEvent;

/**
 * 샘플 앱이 낸 세션 이벤트를 모은다 (EVT-01). 라이브러리는 이벤트를 Spring 이벤트로도 내므로, 앱이 {@code @EventListener}로 받는 것과
 * 같은 길로 받는다. 기본 감사 로그는 그대로 둔다.
 */
public final class E2eSessionEvents implements ApplicationListener<ApplicationEvent> {

    private final List<KeycloakSessionEvent> events = new ArrayList<>();

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof PayloadApplicationEvent<?> payload && payload.getPayload() instanceof KeycloakSessionEvent session) {
            synchronized (events) {
                events.add(session);
            }
        }
    }

    /** 세션 행 id 하나의 이벤트를 받은 순서대로. */
    public List<KeycloakSessionEvent> of(UUID sessionId) {
        synchronized (events) {
            return events.stream().filter(e -> e.sessionId().equals(sessionId)).toList();
        }
    }
}
