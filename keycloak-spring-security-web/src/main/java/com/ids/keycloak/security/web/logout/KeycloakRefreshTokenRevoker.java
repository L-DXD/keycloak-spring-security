package com.ids.keycloak.security.web.logout;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;

/**
 * 로컬 로그아웃 때 Keycloak 리프레시 토큰 폐기 (LOGOUT-06, 옵션 {@code logout.revoke-refresh-token-on-local-logout}, 기본 끔, D13).
 * 앱이 혼자 세션을 끝냈지만 Keycloak에서는 토큰이 아직 살아 있을 수 있는 경우(절대 상한, 토큰 검증 실패)에 부른다.
 * 리프레시 만료(idle)·Keycloak 거절·복호화 실패·재로그인·정리 작업에서는 부르지 않는다.
 * <p>
 * 폐기가 실패해도 로컬 로그아웃은 그대로 끝난다(경고 로그만). 세션 행 잠금이 끝난 뒤에 부른다.
 */
public class KeycloakRefreshTokenRevoker {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRefreshTokenRevoker.class);

    private final boolean enabled;
    private final TokenCipher cipher;
    private final KeycloakTokenClient tokenClient;

    public KeycloakRefreshTokenRevoker(boolean enabled, TokenCipher cipher, KeycloakTokenClient tokenClient) {
        this.enabled = enabled;
        this.cipher = Objects.requireNonNull(cipher);
        this.tokenClient = Objects.requireNonNull(tokenClient);
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** 세션 행의 리프레시 토큰을 풀어 폐기한다. 꺼져 있으면 아무것도 하지 않는다. */
    public void revoke(KeycloakSessionRecord record) {
        if (!enabled) {
            return;
        }
        try {
            revokeQuietly(record, cipher.decrypt(record.refreshToken()));
        } catch (RuntimeException e) {
            log.warn("[KSS] 로컬 로그아웃한 세션의 리프레시 토큰을 풀지 못해 폐기하지 못했습니다 session={} ({})", record.id(), e.getMessage());
        }
    }

    /** 이미 풀어 둔 리프레시 토큰을 폐기한다 (갱신 직후 받은 새 토큰 등). 꺼져 있으면 아무것도 하지 않는다. */
    public void revoke(KeycloakSessionRecord record, String refreshToken) {
        if (enabled) {
            revokeQuietly(record, refreshToken);
        }
    }

    private void revokeQuietly(KeycloakSessionRecord record, String refreshToken) {
        try {
            tokenClient.revoke(refreshToken);
            log.debug("[KSS] 로컬 로그아웃한 세션의 리프레시 토큰을 Keycloak에서 폐기했습니다 session={}", record.id());
        } catch (RuntimeException e) {
            log.warn("[KSS] 리프레시 토큰 폐기에 실패했습니다. 로컬 로그아웃은 끝났습니다 session={} ({})", record.id(), e.getMessage());
        }
    }
}
