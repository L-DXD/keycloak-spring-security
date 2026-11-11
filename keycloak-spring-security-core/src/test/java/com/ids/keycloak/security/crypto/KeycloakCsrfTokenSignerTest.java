package com.ids.keycloak.security.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.session.SessionIds;

class KeycloakCsrfTokenSignerTest {

    private final KeycloakKeyRing ring = new KeycloakKeyRing("k1", Map.of("k1", AesGcmTokenCipherTest.key(1)));
    private final KeycloakCsrfTokenSigner signer = new KeycloakCsrfTokenSigner(ring);

    @Test
    @DisplayName("같은 sid로 만든 토큰은 통하고, 매번 다르다")
    void createAndMatch() {
        String sid = SessionIds.newSid();
        String first = signer.create(sid);
        String second = signer.create(sid);

        assertThat(first).startsWith("k1.").isNotEqualTo(second);
        assertThat(signer.matches(sid, first)).isTrue();
        assertThat(signer.matches(sid, second)).isTrue();
    }

    @Test
    @DisplayName("CSRF-04·06 다른 sid(다른 사용자, 다시 로그인)의 토큰은 통하지 않는다")
    void boundToSid() {
        String token = signer.create(SessionIds.newSid());
        assertThat(signer.matches(SessionIds.newSid(), token)).isFalse();
    }

    @Test
    @DisplayName("모양이 틀리거나 서명을 바꾼 토큰, 모르는 키 id는 통하지 않는다")
    void malformed() {
        String sid = SessionIds.newSid();
        String token = signer.create(sid);
        String tampered = token.substring(0, token.length() - 2) + (token.endsWith("AA") ? "BB" : "AA");

        for (String bad : new String[] {null, "", "k1", "k1.a", "k1.a.b.c", "k9" + token.substring(2), tampered, "k1.%%%.###",
            "x".repeat(300)}) {
            assertThat(signer.matches(sid, bad)).as(String.valueOf(bad)).isFalse();
        }
        assertThat(signer.matches(null, token)).isFalse();
    }

    @Test
    @DisplayName("키를 바꾼 뒤에도 옛 키 토큰을 확인하고, 새 토큰은 새 키로 만든다")
    void keyRotation() {
        String sid = SessionIds.newSid();
        String old = signer.create(sid);
        KeycloakCsrfTokenSigner rotated = new KeycloakCsrfTokenSigner(
            new KeycloakKeyRing("k2", Map.of("k1", AesGcmTokenCipherTest.key(1), "k2", AesGcmTokenCipherTest.key(2))));

        assertThat(rotated.matches(sid, old)).isTrue();
        assertThat(rotated.create(sid)).startsWith("k2.");
    }
}
