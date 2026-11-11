package com.ids.keycloak.security.sample.e2e;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;

import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.session.SessionIds;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** 샘플 앱 DB의 세션 행과 토큰을 들여다본다 (테스트용). */
final class AppSessions {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private AppSessions() {
    }

    static JdbcTemplate jdbc(SampleApps.Running app) {
        return app.context().getBean(JdbcTemplate.class);
    }

    static int count(SampleApps.Running app) {
        return jdbc(app).queryForObject("SELECT count(*) FROM auth_session", Integer.class);
    }

    /** sid 쿠키 값이 가리키는 행 수 (0 또는 1). */
    static int countBySid(SampleApps.Running app, String sid) {
        return jdbc(app).queryForObject("SELECT count(*) FROM auth_session WHERE sid_hash = ?", Integer.class, SessionIds.hash(sid));
    }

    static Map<String, Object> rowBySid(SampleApps.Running app, String sid) {
        return jdbc(app).queryForMap("SELECT * FROM auth_session WHERE sid_hash = ?", SessionIds.hash(sid));
    }

    /** 행의 리프레시 토큰을 앱의 암호로 푼다. */
    static String refreshToken(SampleApps.Running app, String sid) {
        Map<String, Object> row = rowBySid(app, sid);
        return app.context().getBean(TokenCipher.class)
            .decrypt(new EncryptedToken((String) row.get("enc_key_id"), (byte[]) row.get("refresh_token_enc")));
    }

    /** JWT 본문(서명 확인 없이, 테스트에서 값만 볼 때). */
    static JsonNode claims(String jwt) {
        String payload = jwt.split("\\.")[1];
        return json(new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8));
    }

    static JsonNode json(String text) {
        return JSON.readTree(text);
    }

    /** JDBC가 준 시각(TIMESTAMPTZ) 값. */
    static Instant instant(Object value) {
        if (value instanceof java.sql.Timestamp ts) {
            return ts.toInstant();
        }
        if (value instanceof java.time.OffsetDateTime odt) {
            return odt.toInstant();
        }
        throw new IllegalArgumentException("시각이 아니다: " + value);
    }
}
