package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * E2E-01·02: 실제 Keycloak·PostgreSQL·샘플 앱이 뜬다.
 * Docker가 있으면 Testcontainers로, 없으면 KSS_E2E_* 환경 변수로 준 것을 쓴다.
 */
@E2eTest
class E2e01EnvironmentTest {

    private final E2eEnvironment env = E2eEnvironment.get();

    @Test
    @DisplayName("E2E-01·02 Keycloak이 뜨고 realm kss-demo를 읽었다")
    void keycloakIsUpWithRealm() {
        var discovery = new KeycloakAdmin(env).discovery();

        assertThat(discovery.get("issuer").asString()).isEqualTo(env.issuer());
        assertThat(discovery.get("code_challenge_methods_supported").valueStream().map(n -> n.asString()))
            .contains("S256");
        System.out.println("[E2E] Keycloak: " + env.keycloakSource() + " " + env.keycloakUrl());
    }

    @Test
    @DisplayName("E2E-01·02 PostgreSQL이 뜨고 샘플 앱의 Flyway 이력이 있다")
    void databaseIsUpAndMigrated() throws Exception {
        SampleApps.demo();

        try (Connection connection = DriverManager.getConnection(env.dbUrl(), env.dbUsername(), env.dbPassword());
             ResultSet rs = connection.createStatement().executeQuery("SELECT count(*) FROM flyway_schema_history WHERE success")) {
            rs.next();
            assertThat(rs.getInt(1)).isGreaterThanOrEqualTo(1);
        }
        System.out.println("[E2E] PostgreSQL: " + env.dbSource() + " " + env.dbUrl());
    }

    @Test
    @DisplayName("E2E-01 샘플 앱이 테스트 CA 인증서로 HTTPS를 연다 (api.kss.test:8443)")
    void sampleAppServesHttps() throws Exception {
        SampleApps.Running app = SampleApps.demo();

        try (BrowserClient browser = new BrowserClient(env.caCertificate())) {
            BrowserClient.Exchange ping = browser.get(app.url("/api/public/ping"));

            // TLS가 맺어지고 앱이 답한다. 허용·거절은 #118에서 본다
            assertThat(ping.status()).isBetween(200, 499);
            assertThat(ping.uri().getScheme()).isEqualTo("https");
        }
    }
}
