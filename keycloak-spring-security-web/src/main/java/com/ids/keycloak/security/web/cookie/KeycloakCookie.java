package com.ids.keycloak.security.web.cookie;

/**
 * 라이브러리가 쓰는 쿠키 네 가지. 이름은 {@code __Host-{앱 이름}_{suffix}}.
 */
public enum KeycloakCookie {

    /** 세션 id (256비트 난수). 서버에는 SHA-256만 둔다. 수명은 절대 상한 남은 시간 이하. */
    SESSION("sid"),
    /** 액세스 토큰(JWT). 수명은 토큰 남은 시간 이하. */
    ACCESS_TOKEN("at"),
    /** CSRF 토큰 (sid로 서명한 double-submit 값). 수명은 절대 상한 남은 시간 이하. */
    CSRF("csrf"),
    /** 로그인 중 임시 정보(state, PKCE verifier, nonce, 돌아갈 경로). 암호화, 5분. */
    LOGIN("login");

    private final String suffix;

    KeycloakCookie(String suffix) {
        this.suffix = suffix;
    }

    /** 이름 끝부분. 예: {@code sid}. */
    public String suffix() {
        return suffix;
    }
}
