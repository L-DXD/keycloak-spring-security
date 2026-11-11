package com.ids.keycloak.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;

/**
 * 저장소 계약 테스트 (STORE-06). 메모리·H2·PostgreSQL 구현에 같은 테스트를 돌린다.
 */
abstract class KeycloakSessionStoreContract {

    static final Instant NOW = Instant.parse("2026-11-10T03:00:00Z");

    final AesGcmTokenCipher cipher = new AesGcmTokenCipher(new KeycloakKeyRing("k1", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII))));
    KeycloakSessionStore store;
    private ExecutorService executor;

    /** 비어 있는 새 저장소. */
    abstract KeycloakSessionStore createStore();

    /** 행을 저장된 모습 그대로 읽는다 (열 이름 → 값). */
    abstract Map<String, Object> rawRow(UUID id);

    @BeforeEach
    void setUpStore() {
        store = createStore();
        executor = Executors.newFixedThreadPool(8);
    }

    @AfterEach
    void tearDownExecutor() {
        executor.shutdownNow();
    }

    /** 로그인 한 번의 결과: 쿠키에 가는 sid 원문, 리프레시 토큰 원문, 저장한 행. */
    record Login(String sid, String refreshToken, KeycloakSessionRecord record) {
    }

    Login login(String user, String kcSid, Instant createdAt, Duration refreshTtl, Duration absoluteTimeout) {
        String sid = SessionIds.newSid();
        String refreshToken = "eyJhbGciOiJIUzUxMiJ9." + UUID.randomUUID() + ".rt-signature";
        KeycloakSessionRecord record = new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), user, kcSid,
            cipher.encrypt(refreshToken), createdAt.plus(refreshTtl), createdAt, createdAt.plus(absoluteTimeout), null);
        store.insert(record);
        return new Login(sid, refreshToken, record);
    }

    Login login(String user) {
        return login(user, "kc-" + UUID.randomUUID(), NOW, Duration.ofMinutes(30), Duration.ofHours(12));
    }

    @Test
    @DisplayName("STORE-01 행에 sid 원문과 리프레시 토큰 원문이 없다 (sid는 SHA-256, 토큰은 암호문)")
    void store01NoPlainSecrets() {
        Login login = login("user-1");

        Map<String, Object> row = rawRow(login.record().id());
        assertThat(String.valueOf(row.get("sid_hash")).trim()).isEqualTo(SessionIds.hash(login.sid())).hasSize(64);
        for (Object value : row.values()) {
            String text = value instanceof byte[] bytes ? new String(bytes, StandardCharsets.ISO_8859_1) : String.valueOf(value);
            assertThat(text).doesNotContain(login.sid()).doesNotContain(login.refreshToken());
        }
        byte[] stored = (byte[]) row.get("refresh_token_enc");
        assertThat(cipher.decrypt(new EncryptedToken((String) row.get("enc_key_id"), stored))).isEqualTo(login.refreshToken());
    }

    @Test
    @DisplayName("넣은 행을 sid 해시로 그대로 찾는다")
    void insertAndFind() {
        Login login = login("user-1");

        assertThat(store.findBySidHash(SessionIds.hash(login.sid()))).contains(login.record());
        assertThat(store.findBySidHash(SessionIds.hash(SessionIds.newSid()))).isEmpty();
    }

    @Test
    @DisplayName("같은 sid 해시는 두 번 넣지 못한다")
    void duplicateSidHash() {
        Login login = login("user-1");
        KeycloakSessionRecord copy = new KeycloakSessionRecord(UUID.randomUUID(), login.record().sidHash(), "user-2", "kc-x",
            login.record().refreshToken(), NOW.plusSeconds(60), NOW, NOW.plusSeconds(120), null);

        assertThatThrownBy(() -> store.insert(copy)).isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("갱신 결과(새 리프레시 토큰, 만료, 갱신 시각)를 적는다")
    void updateRefreshToken() {
        Login login = login("user-1");
        EncryptedToken renewed = cipher.encrypt("renewed-refresh-token");
        Instant refreshedAt = NOW.plusSeconds(300);

        store.updateRefreshToken(login.record().id(), renewed, refreshedAt.plus(Duration.ofMinutes(30)), refreshedAt);

        KeycloakSessionRecord found = store.findBySidHash(login.record().sidHash()).orElseThrow();
        assertThat(found).isEqualTo(login.record().withRefresh(renewed, refreshedAt.plus(Duration.ofMinutes(30)), refreshedAt));
        assertThat(cipher.decrypt(found.refreshToken())).isEqualTo("renewed-refresh-token");
    }

    @Test
    @DisplayName("로그아웃: sid 해시로 지우고 지운 행을 돌려준다. 두 번째는 빈 값")
    void deleteBySidHash() {
        Login login = login("user-1");
        Login other = login("user-2");

        assertThat(store.deleteBySidHash(login.record().sidHash())).contains(login.record());
        assertThat(store.deleteBySidHash(login.record().sidHash())).isEmpty();
        assertThat(store.findBySidHash(other.record().sidHash())).isPresent();
    }

    @Test
    @DisplayName("back-channel 로그아웃: Keycloak 세션 id(kc_sid)로 그 행들만 지운다")
    void deleteByKcSid() {
        Login first = login("user-1", "kc-shared", NOW, Duration.ofMinutes(30), Duration.ofHours(12));
        Login second = login("user-1", "kc-shared", NOW, Duration.ofMinutes(30), Duration.ofHours(12));
        Login other = login("user-1", "kc-other", NOW, Duration.ofMinutes(30), Duration.ofHours(12));

        List<KeycloakSessionRecord> deleted = store.deleteByKcSid("kc-shared");

        assertThat(deleted).containsExactlyInAnyOrder(first.record(), second.record());
        assertThat(store.deleteByKcSid("kc-shared")).isEmpty();
        assertThat(store.findBySidHash(other.record().sidHash())).isPresent();
    }

    @Test
    @DisplayName("끝난 행도 findBySidHash로 돌려준다 (판단은 부른 쪽)")
    void findReturnsEndedRows() {
        Login ended = login("user-1", "kc-1", NOW.minus(Duration.ofHours(13)), Duration.ofMinutes(30), Duration.ofHours(12));

        assertThat(store.findBySidHash(ended.record().sidHash())).hasValueSatisfying(r -> assertThat(r.isEnded(NOW)).isTrue());
    }

    @Test
    @DisplayName("STORE-04 같은 행을 둘이 동시에 잠그면, 하나가 끝날 때까지 다른 하나가 기다리고 앞의 갱신을 본다")
    void store04LockSerializes() throws Exception {
        Login login = login("user-1");
        String hash = login.record().sidHash();
        CountDownLatch firstInside = new CountDownLatch(1);
        List<String> order = Collections.synchronizedList(new ArrayList<>());
        Instant refreshedAt = NOW.plusSeconds(60);

        Future<?> first = executor.submit(() -> store.lockForRefresh(hash, row -> {
            order.add("first-in");
            firstInside.countDown();
            sleep(400);
            store.updateRefreshToken(row.orElseThrow().id(), cipher.encrypt("rt-2"), refreshedAt.plusSeconds(1800), refreshedAt);
            order.add("first-out");
            return null;
        }));
        assertThat(firstInside.await(10, TimeUnit.SECONDS)).isTrue();
        Future<Optional<KeycloakSessionRecord>> second = executor.submit(() -> store.lockForRefresh(hash, row -> {
            order.add("second-in");
            return row;
        }));

        first.get(10, TimeUnit.SECONDS);
        Optional<KeycloakSessionRecord> seenBySecond = second.get(10, TimeUnit.SECONDS);
        assertThat(order).containsExactly("first-in", "first-out", "second-in");
        assertThat(seenBySecond).hasValueSatisfying(r -> {
            assertThat(r.refreshedAt()).isEqualTo(refreshedAt);
            assertThat(cipher.decrypt(r.refreshToken())).isEqualTo("rt-2");
        });
    }

    @Test
    @DisplayName("STORE-04 잠금 안에서 갱신·삭제를 불러도 막히지 않는다")
    void store04WorkInsideLock() throws Exception {
        Login login = login("user-1");
        String hash = login.record().sidHash();

        Future<Optional<KeycloakSessionRecord>> result = executor.submit(() -> store.lockForRefresh(hash, row -> {
            store.updateRefreshToken(row.orElseThrow().id(), cipher.encrypt("rt-2"), NOW.plusSeconds(1800), NOW);
            return store.deleteBySidHash(hash);
        }));

        assertThat(result.get(10, TimeUnit.SECONDS)).isPresent();
        assertThat(store.findBySidHash(hash)).isEmpty();
        Optional<KeycloakSessionRecord> afterDelete = store.lockForRefresh(hash, row -> row);
        assertThat(afterDelete).isEmpty();
    }

    @Test
    @DisplayName("STORE-05 절대 상한·리프레시 만료가 지난 행 3개, 살아 있는 행 2개 → 정리 작업이 3개만 지우고 사유를 이벤트로 낸다")
    void store05Cleanup() {
        Login absolute1 = login("user-1", "kc-1", NOW.minus(Duration.ofHours(12)), Duration.ofHours(13), Duration.ofHours(12));
        Login absolute2 = login("user-2", "kc-2", NOW.minus(Duration.ofHours(13)), Duration.ofHours(14), Duration.ofHours(12));
        Login idle = login("user-3", "kc-3", NOW.minus(Duration.ofMinutes(40)), Duration.ofMinutes(30), Duration.ofHours(12));
        Login alive1 = login("user-4", "kc-4", NOW.minus(Duration.ofMinutes(10)), Duration.ofMinutes(30), Duration.ofHours(12));
        Login alive2 = login("user-5", "kc-5", NOW.minus(Duration.ofHours(11)), Duration.ofHours(12), Duration.ofHours(12));
        List<KeycloakSessionEvent> events = Collections.synchronizedList(new ArrayList<>());
        KeycloakSessionCleaner cleaner = new KeycloakSessionCleaner(store, events::add, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(10));

        assertThat(cleaner.cleanup()).isEqualTo(3);

        assertThat(store.findBySidHash(alive1.record().sidHash())).isPresent();
        assertThat(store.findBySidHash(alive2.record().sidHash())).isPresent();
        for (Login ended : List.of(absolute1, absolute2, idle)) {
            assertThat(store.findBySidHash(ended.record().sidHash())).isEmpty();
        }
        Map<UUID, KeycloakSessionEndReason> reasons = events.stream()
            .collect(Collectors.toMap(KeycloakSessionEvent::sessionId, KeycloakSessionEvent::endReason));
        assertThat(reasons).containsOnly(
            Map.entry(absolute1.record().id(), KeycloakSessionEndReason.ABSOLUTE_TIMEOUT),
            Map.entry(absolute2.record().id(), KeycloakSessionEndReason.ABSOLUTE_TIMEOUT),
            Map.entry(idle.record().id(), KeycloakSessionEndReason.IDLE));
        assertThat(events).allSatisfy(e -> assertThat(e.type()).isEqualTo(KeycloakSessionEvent.Type.ENDED));

        assertThat(cleaner.cleanup()).isZero();
        assertThat(events).hasSize(3);
    }

    @Test
    @DisplayName("STORE-05 서버 여러 대가 동시에 정리해도 한 행은 한 번만 센다")
    void store05ConcurrentCleanup() throws Exception {
        Set<UUID> ended = new HashSet<>();
        for (int i = 0; i < 40; i++) {
            ended.add(login("user-" + i, "kc-" + i, NOW.minus(Duration.ofHours(13)), Duration.ofHours(14), Duration.ofHours(12)).record().id());
        }
        Login alive = login("user-alive");

        List<Callable<List<KeycloakSessionRecord>>> servers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            servers.add(() -> store.deleteEnded(NOW, 1000));
        }
        List<UUID> deleted = new ArrayList<>();
        for (Future<List<KeycloakSessionRecord>> f : executor.invokeAll(servers, 30, TimeUnit.SECONDS)) {
            f.get().forEach(r -> deleted.add(r.id()));
        }

        assertThat(deleted).hasSize(40).doesNotHaveDuplicates();
        assertThat(new HashSet<>(deleted)).isEqualTo(ended);
        assertThat(store.findBySidHash(alive.record().sidHash())).isPresent();
    }

    @Test
    @DisplayName("STORE-05 limit보다 많으면 limit만큼 지운다")
    void store05Limit() {
        for (int i = 0; i < 5; i++) {
            login("user-" + i, "kc-" + i, NOW.minus(Duration.ofHours(13)), Duration.ofHours(14), Duration.ofHours(12));
        }
        assertThat(store.deleteEnded(NOW, 2)).hasSize(2);
        assertThat(store.deleteEnded(NOW, 10)).hasSize(3);
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    static Map<String, Object> rowOf(KeycloakSessionRecord r) {
        return Map.of("id", r.id(), "sid_hash", r.sidHash(), "keycloak_user_id", r.keycloakUserId(), "kc_sid", r.kcSid(),
            "refresh_token_enc", r.refreshToken().ciphertext(), "enc_key_id", r.refreshToken().keyId(),
            "refresh_expires_at", r.refreshExpiresAt(), "created_at", r.createdAt(), "absolute_expires_at", r.absoluteExpiresAt(),
            "refreshed_at", String.valueOf(r.refreshedAt()));
    }

    static byte[] bytes(Object value) {
        return value instanceof byte[] b ? Arrays.copyOf(b, b.length) : null;
    }
}
