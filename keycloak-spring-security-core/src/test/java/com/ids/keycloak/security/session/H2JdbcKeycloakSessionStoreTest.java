package com.ids.keycloak.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** STORE-06 H2에서 JDBC 저장소 계약. 테이블 이름·앱 열(STORE-07)·스키마 검사도 본다. */
class H2JdbcKeycloakSessionStoreTest extends KeycloakSessionStoreContract {

    private DriverManagerDataSource dataSource;
    private JdbcTemplate jdbc;

    @Override
    KeycloakSessionStore createStore() {
        dataSource = new DriverManagerDataSource("jdbc:h2:mem:kss-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000", "sa", "");
        jdbc = new JdbcTemplate(dataSource);
        JdbcStoreSupport.applySchema(dataSource, "h2", "auth_session");
        JdbcKeycloakSessionStore store = new JdbcKeycloakSessionStore(dataSource, "auth_session");
        store.verifySchema();
        return store;
    }

    @Override
    Map<String, Object> rawRow(UUID id) {
        return jdbc.queryForMap("SELECT * FROM auth_session WHERE id = ?", id);
    }

    @Test
    @DisplayName("STORE-07 앱이 auth_session에 열(NULL 허용)을 더 붙여도 로그인·갱신·로그아웃이 된다")
    void store07AppColumns() {
        jdbc.execute("ALTER TABLE auth_session ADD COLUMN display_name VARCHAR(100)");
        jdbc.execute("ALTER TABLE auth_session ADD COLUMN tenant VARCHAR(20) DEFAULT 'default' NOT NULL");
        JdbcKeycloakSessionStore extended = new JdbcKeycloakSessionStore(dataSource, "auth_session");
        extended.verifySchema();
        store = extended;

        Login login = login("user-1");
        jdbc.update("UPDATE auth_session SET display_name = ? WHERE id = ?", "앱이 적은 이름", login.record().id());
        store.lockForRefresh(login.record().sidHash(), row -> {
            store.updateRefreshToken(row.orElseThrow().id(), cipher.encrypt("rt-2"), NOW.plus(Duration.ofMinutes(30)), NOW);
            return null;
        });

        assertThat(jdbc.queryForObject("SELECT display_name FROM auth_session WHERE id = ?", String.class, login.record().id()))
            .isEqualTo("앱이 적은 이름");
        assertThat(store.deleteBySidHash(login.record().sidHash())).isPresent();
    }

    @Test
    @DisplayName("테이블 이름을 바꿀 수 있다 (session.table-name)")
    void customTableName() {
        JdbcStoreSupport.applySchema(dataSource, "h2", "my_login_session");
        JdbcKeycloakSessionStore custom = new JdbcKeycloakSessionStore(dataSource, "my_login_session");
        custom.verifySchema();
        store = custom;

        Login login = login("user-1");

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM my_login_session", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_session", Integer.class)).isZero();
        assertThat(custom.findBySidHash(login.record().sidHash())).contains(login.record());
    }

    @Test
    @DisplayName("테이블이 없거나 열이 모자라면 스키마 파일 이름을 알려 주며 실패한다")
    void verifySchemaFails() {
        assertThatThrownBy(() -> new JdbcKeycloakSessionStore(dataSource, "no_such_table").verifySchema())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("no_such_table")
            .hasMessageContaining("kss/schema-postgresql.sql");

        jdbc.execute("CREATE TABLE half_session (id UUID PRIMARY KEY, sid_hash CHAR(64))");
        assertThatThrownBy(() -> new JdbcKeycloakSessionStore(dataSource, "half_session").verifySchema())
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("테이블 이름에 SQL을 끼워 넣을 수 없다")
    void rejectsBadTableName() {
        for (String bad : new String[] {"auth_session; DROP TABLE x", "auth-session", "a.b.c", "", " auth_session"}) {
            assertThatThrownBy(() -> new JdbcKeycloakSessionStore(dataSource, bad)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(new JdbcKeycloakSessionStore(dataSource, "public.auth_session").tableName()).isEqualTo("public.auth_session");
    }
}
