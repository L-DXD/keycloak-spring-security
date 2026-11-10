package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.session.JdbcKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;

/**
 * V3-05 (실제 PostgreSQL, 샘플 앱): Flyway로 넣은 세션 테이블을 라이브러리 저장소가 쓴다.
 * 로그인이 행을 만드는 것은 #84에서 본다. 여기서는 앱에 올라간 빈으로 직접 넣고 지운다.
 */
@E2eTest
class E2eSessionStoreTest {

    @Test
    @DisplayName("STORE-01 (PostgreSQL) 앱의 세션 행에 sid 원문과 리프레시 토큰 원문이 없다")
    void store01PlainValuesAreNotStored() {
        SampleApps.Running app = SampleApps.demo();
        KeycloakSessionStore store = app.context().getBean(KeycloakSessionStore.class);
        TokenCipher cipher = app.context().getBean(TokenCipher.class);
        JdbcTemplate jdbc = app.context().getBean(JdbcTemplate.class);
        assertThat(store).isInstanceOf(JdbcKeycloakSessionStore.class);

        String sid = SessionIds.newSid();
        String refreshToken = "eyJhbGciOiJIUzUxMiJ9.e2e-" + UUID.randomUUID() + ".sig";
        KeycloakSessionRecord record = record(sid, cipher.encrypt(refreshToken));
        store.insert(record);
        try {
            Map<String, Object> row = jdbc.queryForMap("SELECT * FROM auth_session WHERE id = ?", record.id());
            assertThat(row.get("sid_hash").toString().trim()).isEqualTo(SessionIds.hash(sid));
            String rowText = row.values().stream()
                .map(v -> v instanceof byte[] b ? new String(b, StandardCharsets.ISO_8859_1) : String.valueOf(v))
                .reduce("", String::concat);
            assertThat(rowText).doesNotContain(sid).doesNotContain(refreshToken);
            assertThat(row.get("enc_key_id")).isEqualTo("e2e");
        } finally {
            store.deleteBySidHash(record.sidHash());
        }
    }

    @Test
    @DisplayName("STORE-07 (PostgreSQL) 앱이 붙인 열(display_name)이 있어도 넣기·갱신·지우기가 되고, 앱 값은 그대로 남는다")
    void store07AppColumnIsKept() {
        SampleApps.Running app = SampleApps.demo();
        KeycloakSessionStore store = app.context().getBean(KeycloakSessionStore.class);
        TokenCipher cipher = app.context().getBean(TokenCipher.class);
        JdbcTemplate jdbc = app.context().getBean(JdbcTemplate.class);

        KeycloakSessionRecord record = record(SessionIds.newSid(), cipher.encrypt("rt-1"));
        store.insert(record);
        jdbc.update("UPDATE auth_session SET display_name = ? WHERE id = ?", "앨리스", record.id());

        Instant refreshedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        store.lockForRefresh(record.sidHash(), row -> {
            store.updateRefreshToken(row.orElseThrow().id(), cipher.encrypt("rt-2"), refreshedAt.plus(Duration.ofMinutes(30)), refreshedAt);
            return null;
        });

        assertThat(jdbc.queryForObject("SELECT display_name FROM auth_session WHERE id = ?", String.class, record.id())).isEqualTo("앨리스");
        assertThat(cipher.decrypt(store.findBySidHash(record.sidHash()).orElseThrow().refreshToken())).isEqualTo("rt-2");
        assertThat(store.deleteBySidHash(record.sidHash())).isPresent();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_session WHERE id = ?", Integer.class, record.id())).isZero();
    }

    private static KeycloakSessionRecord record(String sid, com.ids.keycloak.security.crypto.EncryptedToken refreshToken) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "e2e-user", "e2e-kc-" + UUID.randomUUID(),
            refreshToken, now.plus(Duration.ofMinutes(30)), now, now.plus(Duration.ofHours(12)), null);
    }
}
