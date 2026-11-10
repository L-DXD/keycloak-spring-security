package com.ids.keycloak.security.session;

import java.util.Map;
import java.util.UUID;

/** STORE-06 메모리 저장소도 같은 계약을 지킨다. */
class InMemoryKeycloakSessionStoreTest extends KeycloakSessionStoreContract {

    private InMemoryKeycloakSessionStore memory;

    @Override
    KeycloakSessionStore createStore() {
        memory = new InMemoryKeycloakSessionStore();
        return memory;
    }

    @Override
    Map<String, Object> rawRow(UUID id) {
        // 메모리 저장소는 행 객체를 그대로 들고 있다
        return memory.snapshot().stream().filter(r -> r.id().equals(id)).findFirst().map(KeycloakSessionStoreContract::rowOf).orElseThrow();
    }
}
