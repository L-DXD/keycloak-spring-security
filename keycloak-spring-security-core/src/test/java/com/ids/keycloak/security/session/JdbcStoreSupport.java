package com.ids.keycloak.security.session;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

/** 테스트 DB에 라이브러리 스키마 파일을 넣는다. */
final class JdbcStoreSupport {

    private static final Pattern TABLE = Pattern.compile("\\bauth_session\\b");

    private JdbcStoreSupport() {
    }

    /** jar에 든 스키마 파일({@code kss/schema-*.sql})을 테이블 이름만 바꿔 넣는다. */
    static void applySchema(DataSource dataSource, String dialect, String tableName) {
        try {
            String sql = new ClassPathResource("kss/schema-" + dialect + ".sql").getContentAsString(StandardCharsets.UTF_8);
            String simpleName = tableName.substring(tableName.lastIndexOf('.') + 1);
            sql = sql.replace("ix_auth_session_", "ix_" + simpleName + "_");
            sql = TABLE.matcher(sql).replaceAll(tableName);
            new ResourceDatabasePopulator(new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8))).execute(dataSource);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
