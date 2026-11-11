package com.ids.keycloak.security.event;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CompositeKeycloakSessionEventPublisherTest {

    private static final KeycloakSessionEvent EVENT = new KeycloakSessionEvent(KeycloakSessionEvent.Type.ENDED, UUID.randomUUID(),
        "0f3c9a8e-5b1d-4c1a-9a51-1b9d0f3c9a8e", KeycloakSessionEndReason.LOGOUT, Instant.parse("2026-11-10T00:00:00Z"));

    @Test
    @DisplayName("리스너 하나가 예외를 던져도 나머지에 보내고, 부른 쪽에는 예외가 오지 않는다")
    void failingListenerDoesNotBreakOthers() {
        List<KeycloakSessionEvent> received = new ArrayList<>();
        KeycloakSessionEventPublisher publisher = new CompositeKeycloakSessionEventPublisher(List.of(
            event -> {
                throw new IllegalStateException("감사 테이블 장애");
            },
            received::add));

        publisher.publish(EVENT);

        assertThat(received).containsExactly(EVENT);
    }

    @Test
    @DisplayName("ENDED에만 사유가 있다")
    void endReasonOnlyForEnded() {
        assertThatThrownBy(() -> new KeycloakSessionEvent(KeycloakSessionEvent.Type.ENDED, UUID.randomUUID(), "u", null, Instant.EPOCH))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new KeycloakSessionEvent(KeycloakSessionEvent.Type.CREATED, UUID.randomUUID(), "u",
            KeycloakSessionEndReason.LOGOUT, Instant.EPOCH)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("감사 로그는 사용자 id를 앞 8자만 남긴다")
    void mask() {
        assertThat(KeycloakSessionAuditLogger.mask("0f3c9a8e-5b1d-4c1a-9a51-1b9d0f3c9a8e")).isEqualTo("0f3c9a8e…");
        assertThat(KeycloakSessionAuditLogger.mask("short")).isEqualTo("short");
        assertThat(KeycloakSessionAuditLogger.mask(null)).isEqualTo("-");
        assertThat(KeycloakSessionEndReason.ABSOLUTE_TIMEOUT.code()).isEqualTo("absolute");
    }
}
