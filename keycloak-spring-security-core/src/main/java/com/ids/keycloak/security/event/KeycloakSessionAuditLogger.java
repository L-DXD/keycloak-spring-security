package com.ids.keycloak.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 기본 감사 로그. 로거 이름 {@code com.ids.keycloak.security.audit}, INFO. 사용자 id는 앞 8자만 남긴다.
 * <pre>
 * [KSS] 세션 끝남 reason=absolute session=… user=1a2b3c4d…
 * </pre>
 */
public class KeycloakSessionAuditLogger implements KeycloakSessionEventListener {

    /** 감사 로그 로거 이름. 따로 파일로 빼려면 이 이름을 쓴다. */
    public static final String LOGGER_NAME = "com.ids.keycloak.security.audit";

    private static final Logger log = LoggerFactory.getLogger(LOGGER_NAME);

    @Override
    public void onSessionEvent(KeycloakSessionEvent event) {
        switch (event.type()) {
            case CREATED -> log.info("[KSS] 세션 만듦 session={} user={}", event.sessionId(), mask(event.keycloakUserId()));
            case REFRESHED -> log.debug("[KSS] 세션 갱신 session={} user={}", event.sessionId(), mask(event.keycloakUserId()));
            case ENDED -> log.info("[KSS] 세션 끝남 reason={} session={} user={}", event.endReason().code(), event.sessionId(),
                mask(event.keycloakUserId()));
        }
    }

    /** 사용자 id를 앞 8자만 남긴다. */
    public static String mask(String userId) {
        if (userId == null) {
            return "-";
        }
        return userId.length() <= 8 ? userId : userId.substring(0, 8) + "…";
    }
}
