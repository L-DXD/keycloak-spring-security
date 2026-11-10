package com.ids.keycloak.security.event;

/**
 * 세션이 끝난 사유. 감사 로그에는 {@link #code()}가 남는다 (02 시나리오의 "사유").
 */
public enum KeycloakSessionEndReason {

    /** 사용자가 로그아웃했다 ({@code POST /logout}). */
    LOGOUT("logout"),
    /** Keycloak이 back-channel로 로그아웃을 알렸다. */
    BACKCHANNEL_LOGOUT("backchannel_logout"),
    /** 절대 상한이 지났다. */
    ABSOLUTE_TIMEOUT("absolute"),
    /** 리프레시 토큰이 만료됐다 (Client Session Idle 등). */
    IDLE("idle"),
    /** Keycloak이 갱신을 거절했다 ({@code invalid_grant} 등). */
    REFRESH_FAILED("refresh_failed"),
    /** 액세스 토큰이나 갱신 응답 토큰이 맞지 않았다 (서명, 발급자, sub·sid 불일치 등). */
    INVALID_TOKEN("invalid_token"),
    /** 세션 행의 리프레시 토큰을 풀지 못했다 (모르는 키 id, 위조·손상). */
    DECRYPTION_FAILED("decryption_failed");

    private final String code;

    KeycloakSessionEndReason(String code) {
        this.code = code;
    }

    /** 감사 로그·지표에 쓰는 짧은 이름. */
    public String code() {
        return code;
    }
}
