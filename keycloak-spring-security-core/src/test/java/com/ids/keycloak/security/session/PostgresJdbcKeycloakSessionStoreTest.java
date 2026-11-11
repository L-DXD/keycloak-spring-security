package com.ids.keycloak.security.session;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * STORE-01·06 PostgreSQL에서 JDBC 저장소 계약. 환경 변수 {@code KSS_TEST_DB_URL}(+ USERNAME, PASSWORD)이 있을 때만 돈다.
 * 테스트마다 따로 만든 스키마에 테이블을 만들고 끝나면 스키마를 지운다.
 */
@EnabledIfEnvironmentVariable(named = "KSS_TEST_DB_URL", matches = "jdbc:postgresql:.+")
class PostgresJdbcKeycloakSessionStoreTest extends KeycloakSessionStoreContract {

    private static DriverManagerDataSource dataSource;
    private static JdbcTemplate admin;
    private static final String SCHEMA = "kss_store_test_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    private String table;
    private int counter;

    @BeforeAll
    static void connect() {
        dataSource = new DriverManagerDataSource(System.getenv("KSS_TEST_DB_URL"), System.getenv("KSS_TEST_DB_USERNAME"),
            System.getenv("KSS_TEST_DB_PASSWORD"));
        admin = new JdbcTemplate(dataSource);
        admin.execute("CREATE SCHEMA " + SCHEMA);
    }

    @AfterAll
    static void dropSchema() {
        if (admin != null) {
            admin.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
        }
    }

    @Override
    KeycloakSessionStore createStore() {
        table = SCHEMA + ".auth_session_" + (++counter) + "_" + System.nanoTime() % 100000;
        JdbcStoreSupport.applySchema(dataSource, "postgresql", table);
        JdbcKeycloakSessionStore store = new JdbcKeycloakSessionStore(dataSource, table);
        store.verifySchema();
        return store;
    }

    @Override
    Map<String, Object> rawRow(UUID id) {
        return admin.queryForMap("SELECT * FROM " + table + " WHERE id = ?", id);
    }
}
