package com.ids.keycloak.security.event;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import com.ids.keycloak.security.session.KeycloakSessionRecord;

/**
 * 세션 이벤트: 만들어짐, 갱신됨, 끝남(사유). 토큰 값과 sid 원문은 담지 않는다 (EVT-02).
 * <p>
 * Spring Boot 스타터를 쓰면 {@code @EventListener}로도 받을 수 있다.
 *
 * @param type           종류
 * @param sessionId      세션 행 id
 * @param keycloakUserId 사용자 (액세스 토큰 sub)
 * @param endReason      끝난 사유. {@link Type#ENDED}일 때만 있다
 * @param occurredAt     일어난 시각
 */
public record KeycloakSessionEvent(Type type, UUID sessionId, String keycloakUserId, KeycloakSessionEndReason endReason,
                                   Instant occurredAt) {

    public enum Type {
        CREATED, REFRESHED, ENDED
    }

    public KeycloakSessionEvent {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(keycloakUserId, "keycloakUserId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        if ((type == Type.ENDED) != (endReason != null)) {
            throw new IllegalArgumentException("endReason은 ENDED일 때만 있어야 한다");
        }
    }

    public static KeycloakSessionEvent created(KeycloakSessionRecord record, Instant at) {
        return new KeycloakSessionEvent(Type.CREATED, record.id(), record.keycloakUserId(), null, at);
    }

    public static KeycloakSessionEvent refreshed(KeycloakSessionRecord record, Instant at) {
        return new KeycloakSessionEvent(Type.REFRESHED, record.id(), record.keycloakUserId(), null, at);
    }

    public static KeycloakSessionEvent ended(KeycloakSessionRecord record, KeycloakSessionEndReason reason, Instant at) {
        return new KeycloakSessionEvent(Type.ENDED, record.id(), record.keycloakUserId(), Objects.requireNonNull(reason, "reason"), at);
    }
}
