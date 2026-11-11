package com.ids.keycloak.security.session;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.ids.keycloak.security.crypto.EncryptedToken;

/**
 * DB 세션 저장소 (기본). PostgreSQL과 H2에서 시험했다. 스키마는 스타터 jar의 {@code kss/schema-postgresql.sql}·{@code kss/schema-h2.sql}.
 * <p>
 * 라이브러리는 표준 열만 읽고 쓴다. 앱이 NULL 허용 열을 더 붙여도 된다 (STORE-07).
 * 갱신 잠금은 {@code SELECT ... FOR UPDATE}로 한다 (STORE-04). 트랜잭션은 이 저장소가 따로 연다.
 */
public class JdbcKeycloakSessionStore implements KeycloakSessionStore {

    private static final Pattern TABLE_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}(\\.[A-Za-z_][A-Za-z0-9_]{0,62})?");
    private static final String COLUMNS = "id, sid_hash, keycloak_user_id, kc_sid, refresh_token_enc, enc_key_id, "
        + "refresh_expires_at, created_at, absolute_expires_at, refreshed_at";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final String table;
    private final RowMapper<KeycloakSessionRecord> rowMapper = this::mapRow;

    /**
     * @param dataSource DB
     * @param tableName  테이블 이름 (기본 auth_session). 영문·숫자·_, 스키마는 schema.table
     */
    public JdbcKeycloakSessionStore(DataSource dataSource, String tableName) {
        if (tableName == null || !TABLE_NAME.matcher(tableName).matches()) {
            throw new IllegalArgumentException("테이블 이름이 아니다: " + tableName);
        }
        this.jdbc = new JdbcTemplate(Objects.requireNonNull(dataSource));
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.table = tableName;
    }

    /**
     * 테이블이 있고 표준 열이 모두 있는지 본다. 스타터가 기동 때 부른다.
     *
     * @throws IllegalStateException 테이블·열이 없을 때
     */
    public void verifySchema() {
        try {
            jdbc.query("SELECT " + COLUMNS + " FROM " + table + " WHERE 1 = 0", rs -> null);
        } catch (RuntimeException e) {
            throw new IllegalStateException("세션 테이블 " + table + "이 없거나 열이 모자랍니다. 스타터 jar의 kss/schema-postgresql.sql"
                + "(H2는 kss/schema-h2.sql)을 앱 마이그레이션(Flyway 등)에 넣으세요: " + e.getMessage(), e);
        }
    }

    @Override
    public void insert(KeycloakSessionRecord r) {
        jdbc.update("INSERT INTO " + table + " (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            r.id(), r.sidHash(), r.keycloakUserId(), r.kcSid(), r.refreshToken().ciphertext(), r.refreshToken().keyId(),
            time(r.refreshExpiresAt()), time(r.createdAt()), time(r.absoluteExpiresAt()), time(r.refreshedAt()));
    }

    @Override
    public Optional<KeycloakSessionRecord> findBySidHash(String sidHash) {
        return jdbc.query("SELECT " + COLUMNS + " FROM " + table + " WHERE sid_hash = ?", rowMapper, sidHash).stream().findFirst();
    }

    @Override
    public <T> T lockForRefresh(String sidHash, Function<Optional<KeycloakSessionRecord>, T> work) {
        return tx.execute(status -> {
            Optional<KeycloakSessionRecord> row = jdbc.query("SELECT " + COLUMNS + " FROM " + table + " WHERE sid_hash = ? FOR UPDATE",
                rowMapper, sidHash).stream().findFirst();
            return work.apply(row);
        });
    }

    @Override
    public void updateRefreshToken(UUID id, EncryptedToken refreshToken, Instant refreshExpiresAt, Instant refreshedAt) {
        jdbc.update("UPDATE " + table + " SET refresh_token_enc = ?, enc_key_id = ?, refresh_expires_at = ?, refreshed_at = ? WHERE id = ?",
            refreshToken.ciphertext(), refreshToken.keyId(), time(refreshExpiresAt), time(refreshedAt), id);
    }

    @Override
    public Optional<KeycloakSessionRecord> deleteBySidHash(String sidHash) {
        return tx.execute(status -> {
            Optional<KeycloakSessionRecord> row = findBySidHash(sidHash);
            row.ifPresent(r -> jdbc.update("DELETE FROM " + table + " WHERE id = ?", r.id()));
            return row;
        });
    }

    @Override
    public List<KeycloakSessionRecord> deleteByKcSid(String kcSid) {
        return tx.execute(status -> deleteEach(
            jdbc.query("SELECT " + COLUMNS + " FROM " + table + " WHERE kc_sid = ?", rowMapper, kcSid)));
    }

    @Override
    public List<KeycloakSessionRecord> deleteEnded(Instant now, int limit) {
        List<KeycloakSessionRecord> candidates = jdbc.query("SELECT " + COLUMNS + " FROM " + table
            + " WHERE absolute_expires_at <= ? OR refresh_expires_at <= ? ORDER BY absolute_expires_at FETCH FIRST " + limit + " ROWS ONLY",
            rowMapper, time(now), time(now));
        List<KeycloakSessionRecord> deleted = new ArrayList<>();
        for (KeycloakSessionRecord r : candidates) {
            // 여러 서버가 같이 돌 때 한 행은 한 서버만 지운 것으로 센다
            int count = jdbc.update("DELETE FROM " + table + " WHERE id = ? AND (absolute_expires_at <= ? OR refresh_expires_at <= ?)",
                r.id(), time(now), time(now));
            if (count == 1) {
                deleted.add(r);
            }
        }
        return deleted;
    }

    private List<KeycloakSessionRecord> deleteEach(List<KeycloakSessionRecord> rows) {
        List<KeycloakSessionRecord> deleted = new ArrayList<>();
        for (KeycloakSessionRecord r : rows) {
            if (jdbc.update("DELETE FROM " + table + " WHERE id = ?", r.id()) == 1) {
                deleted.add(r);
            }
        }
        return deleted;
    }

    /** 테이블 이름. */
    public String tableName() {
        return table;
    }

    private KeycloakSessionRecord mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new KeycloakSessionRecord(
            rs.getObject("id", UUID.class),
            rs.getString("sid_hash").trim(),
            rs.getString("keycloak_user_id"),
            rs.getString("kc_sid"),
            new EncryptedToken(rs.getString("enc_key_id"), rs.getBytes("refresh_token_enc")),
            instant(rs, "refresh_expires_at"),
            instant(rs, "created_at"),
            instant(rs, "absolute_expires_at"),
            instant(rs, "refreshed_at"));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private static OffsetDateTime time(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
