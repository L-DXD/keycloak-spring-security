package com.ids.keycloak.security.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SessionIdsTest {

    @Test
    @DisplayName("sid는 43자 base64url이고 매번 다르다")
    void newSid() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            String sid = SessionIds.newSid();
            assertThat(SessionIds.looksLikeSid(sid)).isTrue();
            assertThat(seen.add(sid)).isTrue();
        }
    }

    @Test
    @DisplayName("sid 해시는 SHA-256 hex 64자")
    void hash() {
        assertThat(SessionIds.hash("abc")).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertThat(SessionIds.hash(SessionIds.newSid())).hasSize(64);
    }

    @Test
    @DisplayName("sid 모양이 아니면 DB를 보지 않고 버린다")
    void looksLikeSid() {
        assertThat(SessionIds.looksLikeSid(null)).isFalse();
        assertThat(SessionIds.looksLikeSid("")).isFalse();
        assertThat(SessionIds.looksLikeSid("a".repeat(42))).isFalse();
        assertThat(SessionIds.looksLikeSid("a".repeat(44))).isFalse();
        assertThat(SessionIds.looksLikeSid("a".repeat(42) + "=")).isFalse();
        assertThat(SessionIds.looksLikeSid("a".repeat(42) + "'")).isFalse();
    }
}
