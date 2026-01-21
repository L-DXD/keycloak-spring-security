package com.ids.keycloak.security.model;

import java.util.Collections;
import java.util.Map;
import lombok.Getter;

/**
 * Keycloak에서 OIDC Back-Channel Logout 요청 시 전송되는 Logout Token을 나타내는 모델입니다.
 * 표준 JWT 구조를 따르며, 백채널 로그아웃 특유의 클레임 정보를 포함합니다.
 */
@Getter
public class KeycloakLogoutToken {

    /**
     * OIDC Back-Channel Logout 이벤트 식별자 URI
     */
    private static final String BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private final String issuer;
    private final String subject;
    private final String sessionId;
    private final Map<String, Object> events;
    private final Map<String, Object> claims;

    public KeycloakLogoutToken(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(claims);
        this.issuer = (String) claims.get("iss");
        this.subject = (String) claims.get("sub");
        this.sessionId = (String) claims.get("sid");
        this.events = (Map<String, Object>) claims.get("events");
    }

    /**
     * 이 토큰이 유효한 백채널 로그아웃 토큰인지 확인합니다.
     * 'events' 클레임 내에 표준 로그아웃 이벤트 키가 존재해야 합니다.
     *
     * @return 로그아웃 토큰 여부
     */
    public boolean isLogoutToken() {
        if (events == null) {
            return false;
        }
        return events.containsKey(BACK_CHANNEL_LOGOUT_EVENT);
    }

    @Override
    public String toString() {
        return "KeycloakLogoutToken{" +
            "sub='" + subject + "'" +
            ", sid='" + sessionId + "'" +
            ", iss='" + issuer + "'" +
            '}';
    }
}
