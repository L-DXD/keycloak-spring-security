package com.ids.keycloak.security.web.refresh;

import static com.ids.keycloak.security.web.refresh.RefreshFixtures.KEYS;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.sql.DataSource;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.session.JdbcKeycloakSessionStore;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshResult.Status;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.FakeTokenClient;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.FakeValidator;
import com.ids.keycloak.security.web.refresh.RefreshFixtures.MovingClock;

/**
 * REFRESH-02·09 (통합): JDBC 세션 저장소(행 잠금)로 같은 세션의 동시 갱신이 Keycloak을 한 번만 부르는지 본다.
 */
class KeycloakRefreshConcurrencyTest {

    static DataSource h2() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource("jdbc:h2:mem:kss-refresh-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1",
            "sa", "");
        new ResourceDatabasePopulator(new ClassPathResource("kss/schema-h2.sql")).execute(dataSource);
        return dataSource;
    }

    @Test
    @DisplayName("REFRESH-02·09 (통합) 만료된 세션에 요청 5개가 동시에 와도 Keycloak 갱신은 1번, 5개 모두 같은 새 토큰을 받는다")
    void concurrentRefreshCallsKeycloakOnce() throws Exception {
        MovingClock clock = new MovingClock();
        JdbcKeycloakSessionStore store = new JdbcKeycloakSessionStore(h2(), "auth_session");
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(KEYS);
        FakeTokenClient keycloak = new FakeTokenClient(rt -> null);
        keycloak.delayMillis = 300;
        KeycloakRefreshService service = new KeycloakRefreshService(store, cipher, keycloak, new FakeValidator(clock), e -> {
        }, clock, Duration.ofSeconds(10));
        String sid = RefreshFixtures.loggedIn(store, cipher);

        ExecutorService pool = Executors.newFixedThreadPool(5);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<KeycloakRefreshResult>> futures = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            futures.add(pool.submit((Callable<KeycloakRefreshResult>) () -> {
                start.await();
                return service.refresh(sid);
            }));
        }
        start.countDown();
        List<KeycloakRefreshResult> results = new ArrayList<>();
        for (Future<KeycloakRefreshResult> future : futures) {
            results.add(future.get());
        }
        pool.shutdown();

        assertThat(keycloak.calls).hasValue(1);
        assertThat(results).extracting(KeycloakRefreshResult::status).containsOnly(Status.REFRESHED, Status.REUSED)
            .filteredOn(s -> s == Status.REFRESHED).hasSize(1);
        assertThat(results).extracting(r -> r.accessToken().getTokenValue()).containsOnly("at-1");
    }
}
